use crate::Credentials;
use backoff::backoff::Backoff;
use backoff::ExponentialBackoff;
use failure::{format_err, Error, ResultExt};
use hawk;
use reqwest;
use reqwest::header::HeaderValue;
use serde_json::Value;
use std::str::FromStr;
use std::time::Duration;
use tokio;

/// Client is the entry point into all the functionality in this package. It
/// contains authentication credentials, and a service endpoint, which are
/// required for all HTTP operations.
#[derive(Debug, Clone)]
pub struct Client {
    /// The credentials associated with this client and used for requests.
    /// If None, then unauthenticated requests are made.  These may be modified
    /// and will take effect on the next request made with this client.
    pub credentials: Option<Credentials>,
    /// Retry information.  Note that some of this information cannot be changed
    /// after construction.
    retry: Retry,
    /// The base URL for requests to the selected service / api version
    base_url: reqwest::Url,
    /// Reqwest client
    client: reqwest::Client,
}

/// Configuration for a client's automatic retrying
#[derive(Debug, Clone)]
pub struct Retry {
    /// Number of retries for transient errors
    pub retries: u32,

    /// Maximum interval between retries (used in tests to make retries quick)
    pub max_interval: Duration,

    /// Timeout for each HTTP request
    pub timeout: Duration,
}

impl Client {
    /// Instatiate a new client for a taskcluster service.  The `root_url` is the Taskcluster
    /// deployment root url, `service_name` is the name of the service, and `api_version` is the
    /// service's api version.
    pub fn new<'b>(
        root_url: &str,
        service_name: &str,
        api_version: &str,
        credentials: Option<Credentials>,
        retry: Option<Retry>,
    ) -> Result<Client, Error> {
        let retry = retry.unwrap_or(Retry {
            retries: 5,
            max_interval: Duration::from_millis(backoff::default::MAX_INTERVAL_MILLIS),
            timeout: Duration::from_secs(30),
        });
        let timeout = retry.timeout;

        Ok(Client {
            credentials,
            retry,
            base_url: reqwest::Url::parse(root_url)
                .context(root_url.to_owned())?
                .join(&format!("/api/{}/{}/", service_name, api_version))
                .context(format!("adding /api/{}/{}", service_name, api_version))?,
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(timeout)
                .build()?,
        })
    }

    /// Make a request to the service for which this client was configured.
    /// While the per-service methods are generally more convenient, this
    /// method can be used to call a path on the service directly.
    ///
    /// The `path` argument is relative to the
    /// `<rootUrl>/api/<serviceName>/<apiVersion>`
    /// path for the configured service, and must not begin with `/`.
    pub async fn request(
        &self,
        method: &str,
        path: &str,
        query: Option<Vec<(&str, &str)>>,
        body: Option<&Value>,
    ) -> Result<reqwest::Response, Error> {
        let mut backoff = ExponentialBackoff::default();
        backoff.max_elapsed_time = None; // we count retries instead
        backoff.max_interval = self.retry.max_interval;
        backoff.reset();

        let req = self.build_request(method, path, query, body)?;
        let url = req.url().as_str();

        let mut retries = self.retry.retries;
        loop {
            let req = req
                .try_clone()
                .ok_or_else(|| format_err!("Cannot clone the request {}", url))?;

            let retry_for;
            match self.client.execute(req).await {
                // From the request docs for Client::execute:
                // > This method fails if there was an error while sending request, redirect loop
                // > was detected or redirect limit was exhausted.
                // All cases where there's a successful HTTP response are Ok(..).
                Err(e) => {
                    retry_for = e;
                }

                // Retry for server errors
                Ok(resp) if resp.status().is_server_error() => {
                    retry_for = resp.error_for_status().err().unwrap();
                }

                // Anything else is OK.
                Ok(resp) => {
                    return Ok(resp);
                }
            };

            // if we got here, we are going to retry, or return the error if we are done
            // retrying.

            retries -= 1;
            if retries <= 0 {
                return Err(retry_for.into());
            }

            match backoff.next_backoff() {
                Some(duration) => tokio::time::delay_for(duration).await,
                None => return Err(retry_for.into()),
            }
        }
    }

    fn build_request(
        &self,
        method: &str,
        path: &str,
        query: Option<Vec<(&str, &str)>>,
        body: Option<&Value>,
    ) -> Result<reqwest::Request, Error> {
        if path.starts_with("/") {
            panic!("path must not start with `/`");
        }
        let mut url = self.base_url.join(path)?;

        if let Some(q) = query {
            url.query_pairs_mut().extend_pairs(q);
        }

        let meth = reqwest::Method::from_str(method)?;

        let req = self.client.request(meth, url);

        let req = match body {
            Some(b) => req.json(&b),
            None => req,
        };

        let req = req.build()?;

        match self.credentials {
            Some(ref c) => {
                let creds = hawk::Credentials {
                    id: c.client_id.clone(),
                    key: hawk::Key::new(&c.access_token, hawk::SHA256)
                        .context(c.client_id.to_owned())?,
                };

                self.sign_request(&creds, req)
            }
            None => Ok(req),
        }
    }

    fn sign_request(
        &self,
        creds: &hawk::Credentials,
        req: reqwest::Request,
    ) -> Result<reqwest::Request, Error> {
        let host = req.url().host_str().ok_or(format_err!(
            "The root URL {} doesn't contain a host",
            req.url(),
        ))?;

        let port = req.url().port_or_known_default().ok_or(format_err!(
            "Unkown port for protocol {}",
            self.base_url.scheme()
        ))?;

        let signed_req_builder =
            hawk::RequestBuilder::new(req.method().as_str(), host, port, req.url().path());

        let payload_hash;
        let signed_req_builder = match req.body() {
            Some(ref b) => {
                let b = b.as_bytes().ok_or(format_err!("Body is a stream???"))?;
                payload_hash = hawk::PayloadHasher::hash("text/json", hawk::SHA256, b)?;
                signed_req_builder.hash(&payload_hash[..])
            }
            None => signed_req_builder,
        };

        let header = signed_req_builder.request().make_header(&creds)?;

        let token = HeaderValue::from_str(format!("Hawk {}", header).as_str()).context(header)?;

        let mut req = req;
        req.headers_mut().insert("Authorization", token);
        Ok(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::AUTHORIZATION;
    use httptest::{matchers::*, responders::*, Expectation, Server};
    use serde_json::json;
    use std::fmt;
    use std::net::SocketAddr;
    use tokio;

    #[tokio::test]
    async fn test_simple_request() -> Result<(), Error> {
        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/api/queue/v1/ping"))
                .respond_with(status_code(200)),
        );
        let root_url = format!("http://{}", server.addr());

        let client = Client::new(&root_url, "queue", "v1", None, None)?;
        let resp = client.request("GET", "ping", None, None).await?;
        assert!(resp.status().is_success());
        Ok(())
    }

    /// An httptest matcher that will check Hawk authentication with the given cedentials.
    pub fn signed_with(creds: Credentials, addr: SocketAddr) -> SignedWith {
        SignedWith(creds, addr)
    }

    #[derive(Debug)]
    pub struct SignedWith(Credentials, SocketAddr);

    impl<B> Matcher<http::Request<B>> for SignedWith {
        fn matches(&mut self, input: &http::Request<B>, _ctx: &mut ExecutionContext) -> bool {
            let auth_header = input.headers().get(AUTHORIZATION).unwrap();
            let auth_header = auth_header.to_str().unwrap();
            if !auth_header.starts_with("Hawk ") {
                println!("Authorization header does not start with Hawk");
                return false;
            }
            let auth_header: hawk::Header = auth_header[5..].parse().unwrap();

            let host = format!("{}", self.1.ip());
            let hawk_req = hawk::RequestBuilder::new(
                input.method().as_str(),
                &host,
                self.1.port(),
                input.uri().path(),
            )
            .request();

            let key = hawk::Key::new(&self.0.access_token, hawk::SHA256).unwrap();

            if !hawk_req.validate_header(&auth_header, &key, std::time::Duration::from_secs(1)) {
                println!("Validation failed");
                return false;
            }

            true
        }

        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            <Self as fmt::Debug>::fmt(self, f)
        }
    }

    #[tokio::test]
    async fn test_simple_request_with_perm_creds() -> Result<(), Error> {
        let creds = Credentials::new("clientId", "accessToken");

        let server = Server::run();
        server.expect(
            Expectation::matching(all_of![
                request::method_path("GET", "/api/queue/v1/ping"),
                signed_with(creds.clone(), server.addr()),
            ])
            .respond_with(status_code(200)),
        );
        let root_url = format!("http://{}", server.addr());

        let client = Client::new(&root_url, "queue", "v1", Some(creds), None)?;
        let resp = client.request("GET", "ping", None, None).await?;
        assert!(resp.status().is_success());
        Ok(())
    }

    #[tokio::test]
    async fn test_query() -> Result<(), Error> {
        let server = Server::run();
        server.expect(
            Expectation::matching(all_of![
                request::method_path("GET", "/api/queue/v1/test"),
                request::query(url_decoded(contains(("taskcluster", "test")))),
                request::query(url_decoded(contains(("client", "rust")))),
            ])
            .respond_with(status_code(200)),
        );
        let root_url = format!("http://{}", server.addr());

        let client = Client::new(&root_url, "queue", "v1", None, None)?;
        let resp = client
            .request(
                "GET",
                "test",
                Some(vec![("taskcluster", "test"), ("client", "rust")]),
                None,
            )
            .await?;
        assert!(resp.status().is_success());
        Ok(())
    }

    #[tokio::test]
    async fn test_body() -> Result<(), Error> {
        let body = json!({"hello": "world"});

        let server = Server::run();
        server.expect(
            Expectation::matching(all_of![
                request::method_path("POST", "/api/queue/v1/test"),
                request::body(json_decoded(eq(body.clone()))),
            ])
            .respond_with(status_code(200)),
        );
        let root_url = format!("http://{}", server.addr());

        let client = Client::new(&root_url, "queue", "v1", None, None)?;
        let resp = client.request("POST", "test", None, Some(&body)).await?;
        assert!(resp.status().is_success());
        Ok(())
    }

    const RETRY_FAST: Retry = Retry {
        retries: 6,
        max_interval: Duration::from_millis(1),
        timeout: Duration::from_secs(1),
    };

    #[tokio::test]
    async fn test_500_retry() -> Result<(), Error> {
        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/api/queue/v1/test"))
                .times(6)
                .respond_with(status_code(500)),
        );
        let root_url = format!("http://{}", server.addr());
        let client = Client::new(&root_url, "queue", "v1", None, Some(RETRY_FAST.clone()))?;

        let result = client.request("GET", "test", None, None).await;
        println!("{:?}", result);
        assert!(result.is_err());
        let reqw_err: reqwest::Error = result.err().unwrap().downcast()?;
        assert_eq!(reqw_err.status().unwrap(), 500);
        Ok(())
    }

    #[tokio::test]
    async fn test_400_no_retry() -> Result<(), Error> {
        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/api/queue/v1/test"))
                .times(1)
                .respond_with(status_code(400)),
        );
        let root_url = format!("http://{}", server.addr());
        let client = Client::new(&root_url, "queue", "v1", None, Some(RETRY_FAST.clone()))?;

        let resp = client.request("GET", "test", None, None).await?;
        assert_eq!(resp.status(), 400);
        Ok(())
    }

    #[tokio::test]
    async fn test_303_no_follow() -> Result<(), Error> {
        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/api/queue/v1/test"))
                .times(1)
                // should not follow this redirect..
                .respond_with(status_code(303).insert_header("location", "http://httpstat.us/404")),
        );
        let root_url = format!("http://{}", server.addr());
        let client = Client::new(&root_url, "queue", "v1", None, Some(RETRY_FAST.clone()))?;

        let resp = client.request("GET", "test", None, None).await?;
        assert_eq!(resp.status(), 303);
        Ok(())
    }
}
