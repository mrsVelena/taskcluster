package wsmux

import (
	"bytes"
	"encoding/binary"
	"io/ioutil"
	"net"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

/*
TODO: Add ping and pong handlers
*/

const (
	defaultQueueSize            = 20
	defaultStreamQueueSize      = 20
	defaultKeepAliveInterval    = 30 * time.Second
	defaultStreamAcceptDeadline = 30 * time.Second
)

// Session implements net.Listener. Allows creating and acception multiplexed streams over ws
type Session struct {
	mu       sync.Mutex
	streams  map[uint32]*stream
	streamCh chan *stream
	conn     *websocket.Conn

	sendLock sync.Mutex

	keepAliveInterval    time.Duration
	streamAcceptDeadline time.Duration

	logger Logger

	nextID uint32

	closed chan struct{} // nil channel

	closeConn bool

	remoteCloseCallback func()
}

func (s *Session) send(f frame) error {
	select {
	case <-s.closed:
		return ErrSessionClosed
	default:
	}
	s.sendLock.Lock()
	defer s.sendLock.Unlock()
	err := s.conn.WriteMessage(websocket.BinaryMessage, f.Write())
	if err != nil {
		s.logger.Printf("wrote %v", f)
	}
	return err
}

func newSession(conn *websocket.Conn, server bool, conf Config) *Session {
	s := &Session{}
	s.conn = conn
	s.streams = make(map[uint32]*stream)
	s.streamCh = make(chan *stream, defaultStreamQueueSize)

	s.closed = make(chan struct{})
	s.closeConn = true

	s.remoteCloseCallback = conf.RemoteCloseCallback

	if conf.KeepAliveInterval == 0 {
		s.keepAliveInterval = defaultKeepAliveInterval
	} else {
		s.keepAliveInterval = conf.KeepAliveInterval
	}

	if conf.StreamAcceptDeadline == 0 {
		s.streamAcceptDeadline = defaultStreamAcceptDeadline
	} else {
		s.streamAcceptDeadline = conf.StreamAcceptDeadline
	}

	if server {
		s.nextID = 0
	} else {
		s.nextID = 1
	}

	if conf.Log == nil {
		s.logger = &nilLogger{}
	} else {
		s.logger = conf.Log
	}

	s.conn.SetCloseHandler(s.closeHandler)

	go s.recvLoop()
	return s
}

// Accept is used to accept an incoming stream
func (s *Session) Accept() (net.Conn, error) {

	select {
	case <-s.closed:
		return nil, ErrSessionClosed
	case str := <-s.streamCh:
		return str, nil
	}
}

// Open creates a new stream
func (s *Session) Open() (net.Conn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	select {
	case <-s.closed:
		return nil, ErrSessionClosed
	default:
	}

	id := s.nextID
	// increment here so that we can wait safely
	s.nextID += 2
	if _, ok := s.streams[id]; ok {
		return nil, ErrDuplicateStream
	}

	str := newStream(id, s)
	s.streams[id] = str

	if err := s.send(newSynFrame(id)); err != nil {
		s.nextID -= 2
		return nil, err
	}
	// unlock mutex and wait
	s.mu.Unlock()

	select {
	case <-str.accepted:
		s.mu.Lock()
		return str, nil
	case <-s.closed:
		s.mu.Lock()
		// state of s.nextID doesn't matter here
		delete(s.streams, id)
		return nil, ErrSessionClosed
	case <-time.After(s.streamAcceptDeadline):
		s.mu.Lock()
		// nextID can be cyclically reused, and previous instance
		// may be in use by a different stream
		delete(s.streams, id)
		return nil, ErrAcceptTimeout
	}

}

// Close closes the current session and underlying connection
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if channel has been closed
	select {
	case <-s.closed:
		return ErrSessionClosed
	default:
	}

	close(s.closed)
	if s.closeConn {
		_ = s.conn.Close()
	}

	for _, v := range s.streams {
		_ = v.Close()
	}
	s.streams = nil

	return nil
}

// Addr used for implementing net.Listener
func (s *Session) Addr() net.Addr {
	return s.conn.LocalAddr()
}

func (s *Session) closeHandler(code int, text string) error {
	s.logger.Printf("ws conn closed: code %d : %s", code, text)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeConn = false
	return s.Close()
}

func (s *Session) recvLoop() {
	for {
		select {
		case <-s.closed:
			return
		default:
		}

		t, msgReader, err := s.conn.NextReader()
		if err != nil {
			_ = s.Close()
			break
		}
		if t != websocket.BinaryMessage {
			continue
		}

		h, err := getHeader(msgReader)
		id, msgType := h.id(), h.msg()

		switch msgType {
		//Used for creating a new stream
		case msgSYN:
			s.mu.Lock()
			if _, ok := s.streams[id]; ok {
				s.logger.Printf("received duplicate syn frame for stream %d", id)
				s.mu.Unlock()
				break
			}

			str := newStream(id, s)
			// no point in locking here
			str.accept(DefaultCapacity)

			s.streams[id] = str
			if err := s.send(newAckFrame(id, uint32(DefaultCapacity))); err != nil {
				s.logger.Printf("error accepting stream %d", id)
				_ = s.Close()
				return
			}
			s.asyncPushStream(str)
			s.mu.Unlock()

		//received data
		case msgDAT:
			s.mu.Lock()
			str, ok := s.streams[id]
			s.mu.Unlock()
			if !ok {
				s.logger.Printf("received data frame for unknown stream %d", id)
				break
			}
			b, err := ioutil.ReadAll(msgReader)
			if err != nil {
				s.logger.Print(err)
				break
			}
			str.addToBuffer(b)
			s.logger.Printf("received DAT frame on stream %d: %v", id, bytes.NewBuffer(b))

		//received ack frame
		case msgACK:
			s.mu.Lock()
			str, ok := s.streams[id]
			s.mu.Unlock()
			s.logger.Printf("received ack frame")
			if !ok {
				s.logger.Printf("received ack frame for unknown stream %d", id)
				break
			}

			b := make([]byte, 4)
			_, err := msgReader.Read(b)
			if err != nil {
				s.logger.Print(err)
				break
			}
			read := binary.LittleEndian.Uint32(b)
			select {
			case <-str.accepted:
				s.logger.Printf("received ack frame: id %d: remote read %d bytes", id, read)
				str.updateRemoteCapacity(read)
			default:
				// close str.accepted to accept stream
				s.logger.Printf("accepting stream")
				str.accept(read)
				break
			}

		// received fin frame
		case msgFIN:
			s.mu.Lock()
			str, ok := s.streams[id]
			s.mu.Unlock()
			if !ok {
				s.logger.Printf("received fin frame for unknown stream %d", id)
				break
			}

			err := str.setRemoteClosed()
			if err != nil {
				s.logger.Print(err)
			}
		}

	}
}

func (s *Session) removeStream(id uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.streams[id]; ok {
		delete(s.streams, id)
	}
}

func (s *Session) asyncPushStream(str *stream) {
	select {
	case s.streamCh <- str:
	default:
	}
}
