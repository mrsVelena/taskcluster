use base64;
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::sha2::Sha256;

pub(crate) fn gen_temp_access_token(perm_access_token: &str, seed: &str) -> String {
    let mut hash = Hmac::new(Sha256::new(), perm_access_token.as_bytes());
    hash.input(seed.as_bytes());
    base64::encode_config(hash.result().code(), base64::URL_SAFE_NO_PAD)
}
