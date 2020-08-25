use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::sha2::Sha256;
use failure::{err_msg, format_err, Error, ResultExt};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json;
use slugid;
use std::env;
use std::iter::{FromIterator, IntoIterator, Iterator};
use std::time::{Duration, SystemTime};

/// Credentials represents the set of credentials required to access protected
/// Taskcluster HTTP APIs.
#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    /// Client ID
    pub client_id: String,
    /// Access token
    pub access_token: String,
    /// Certificate for temporary credentials
    #[serde(deserialize_with = "parse_certificate")]
    pub certificate: Option<String>,
    /// AuthorizedScopes if set to None, is ignored. Otherwise, it should be a
    /// subset of the scopes that the ClientId already has, and restricts the
    /// Credentials to only having these scopes. This is useful when performing
    /// actions on behalf of a client which has more restricted scopes. Setting
    /// to None is not the same as setting to an empty array. If AuthorizedScopes
    /// is set to an empty array rather than None, this is equivalent to having
    /// no scopes at all.
    /// See https://docs.taskcluster.net/docs/manual/design/apis/hawk/authorized-scopes
    #[serde(rename = "authorizedScopes")]
    pub scopes: Option<Vec<String>>,
}

// deserialize the certificate. If the certificate is an empty string, parse it as None
fn parse_certificate<'a, D: Deserializer<'a>>(d: D) -> Result<Option<String>, D::Error> {
    Deserialize::deserialize(d).map(|cert: Option<String>| {
        cert.and_then(|cert| if cert.is_empty() { None } else { Some(cert) })
    })
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub(crate) struct Certificate {
    pub version: u32,
    pub scopes: Option<Vec<String>>,
    pub start: i64,
    pub expiry: i64,
    pub seed: String,
    pub signature: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    #[serde(default)]
    pub issuer: String,
}

fn gen_temp_access_token(perm_access_token: &str, seed: &str) -> String {
    let mut hash = Hmac::new(Sha256::new(), perm_access_token.as_bytes());
    hash.input(seed.as_bytes());
    base64::encode_config(hash.result().code(), base64::URL_SAFE_NO_PAD)
}

fn collect_scopes<R: FromIterator<String>>(
    scopes: impl IntoIterator<Item = impl AsRef<str>>,
) -> Option<R> {
    Some(scopes.into_iter().map(|s| s.as_ref().to_string()).collect())
}

impl Credentials {
    /// Create a new Credentials object from environment variables:
    ///
    /// * `TASKCLUSTER_CLIENT_ID`
    /// * `TASKCLUSTER_ACCESS_TOKEN`
    /// * `TASKCLUSTER_CERTIFICATE` (optional)
    pub fn from_env() -> Result<Credentials, Error> {
        let client_id = env::var("TASKCLUSTER_CLIENT_ID").context("TASKCLUSTER_CLIENT_ID")?;
        let access_token =
            env::var("TASKCLUSTER_ACCESS_TOKEN").context("TASKCLUSTER_ACCESS_TOKEN")?;

        let certificate = match env::var("TASKCLUSTER_CERTIFICATE") {
            Err(err) => match err {
                env::VarError::NotPresent => None,
                _ => {
                    return Err(format_err!(
                        "Cannot read environment variable 'TASKCLUSTER_CERTIFICATE': {}",
                        err
                    ))
                }
            },
            Ok(cert) if cert.is_empty() => None,
            Ok(cert) => Some(cert),
        };

        Ok(Credentials {
            client_id,
            access_token,
            certificate,
            scopes: None,
        })
    }

    /// Create a new Credentials object without associated scopes.
    ///
    /// Examples:
    ///
    /// ```
    /// use taskcluster::Credentials;
    /// let _ = Credentials::new("my_client_id", "my_access_token");
    /// ```
    pub fn new(client_id: &str, access_token: &str) -> Credentials {
        Credentials {
            client_id: String::from(client_id),
            access_token: String::from(access_token),
            certificate: None,
            scopes: None,
        }
    }

    /// Create a new Credentials object with the given scopes. The scopes parameter must be a collection
    /// in which items implements AsRef<str> (&str and String are such types).
    ///
    /// Examples:
    /// ```
    /// use taskcluster::Credentials;
    /// let _ = Credentials::new_with_scopes("my_client_id", "my_access_token", &["scope1", "scope2", "scope3"]);
    /// ```
    ///
    /// ```
    /// use taskcluster::Credentials;
    /// let scopes: Vec<_> = vec!["scope1", "scope2", "scope3"].into_iter().collect();
    /// let _ = Credentials::new_with_scopes("my_client_id", "my_access_token", scopes);
    /// ```
    pub fn new_with_scopes(
        client_id: &str,
        access_token: &str,
        scopes: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Credentials {
        Credentials {
            client_id: String::from(client_id),
            access_token: String::from(access_token),
            certificate: None,
            scopes: collect_scopes(scopes),
        }
    }

    /// CreateNamedTemporaryCredentials generates temporary credentials from permanent
    /// credentials, valid for the given duration, starting immediately.  The
    /// temporary credentials' scopes must be a subset of the permanent credentials'
    /// scopes. The duration may not be more than 31 days. Any authorized scopes of
    /// the permanent credentials will be passed through as authorized scopes to the
    /// temporary credentials, but will not be restricted via the certificate.
    ///
    /// Note that the auth service already applies a 5 minute clock skew to the
    /// start and expiry times in
    /// https://github.com/taskcluster/taskcluster-auth/pull/117 so no clock skew is
    /// applied in this method, nor should be applied by the caller.
    ///
    /// See https://docs.taskcluster.net/docs/manual/design/apis/hawk/temporary-credentials
    pub fn create_named_temp_creds(
        &self,
        temp_client_id: &str,
        duration: Duration,
        scopes: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<Credentials, Error> {
        if duration > Duration::from_secs(3600) * 24 * 31 {
            return Err(err_msg("Duration must be at most 31 days"));
        }

        if let Some(_) = self.certificate {
            return Err(err_msg(
                "Can only create temporary credentials from permanent credentials",
            ));
        }

        let start = SystemTime::now();
        let expiry = start + duration;

        let mut cert = Certificate {
            version: 1,
            scopes: collect_scopes(scopes),
            start: start
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64,
            expiry: expiry
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64,
            seed: slugid::v4() + &slugid::v4(),
            signature: String::new(),
            // include the issuer iff this is a named credential
            issuer: if temp_client_id != "" {
                self.client_id.clone()
            } else {
                String::new()
            },
        };

        cert.sign(&self.access_token, &temp_client_id);

        let temp_access_token = gen_temp_access_token(&self.access_token, &cert.seed);

        Ok(Credentials {
            client_id: if temp_client_id == "" {
                self.client_id.clone()
            } else {
                String::from(temp_client_id)
            },
            access_token: temp_access_token,
            certificate: Some(serde_json::to_string(&cert)?),
            scopes: self.scopes.clone(),
        })
    }

    /// CreateTemporaryCredentials is an alias for CreateNamedTemporaryCredentials
    /// with an empty name.
    pub fn create_temp_creds(
        &self,
        duration: Duration,
        scopes: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<Credentials, Error> {
        self.create_named_temp_creds("", duration, scopes)
    }
}

impl Certificate {
    pub(crate) fn sign(&mut self, access_token: &str, temp_client_id: &str) {
        let mut lines = vec![format!("version:{}", self.version)];

        if !self.issuer.is_empty() {
            lines.extend_from_slice(&[
                format!("clientId:{}", temp_client_id),
                format!("issuer:{}", self.issuer),
            ]);
        }

        lines.extend_from_slice(&[
            format!("seed:{}", self.seed),
            format!("start:{}", self.start),
            format!("expiry:{}", self.expiry),
            String::from("scopes:"),
        ]);

        if let Some(s) = &self.scopes {
            lines.extend_from_slice(s.clone().into_iter().collect::<Vec<String>>().as_slice());
        }

        let mut hash = Hmac::new(Sha256::new(), access_token.as_bytes());
        hash.input(lines.join("\n").as_bytes());
        self.signature = base64::encode(hash.result().code());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono;
    use lazy_static::lazy_static;
    use serde::{Deserialize, Serialize};
    use std::fs;
    use std::path;
    use std::sync::{LockResult, Mutex, MutexGuard};
    use std::time;

    // environment is global to the process, so we need to ensure that only one test uses
    // it at a time.
    lazy_static! {
        static ref ENV_LOCK: Mutex<()> = Mutex::new(());
    }

    fn clear_env() -> LockResult<MutexGuard<'static, ()>> {
        let guard = ENV_LOCK.lock();
        for (key, _) in env::vars() {
            if key.starts_with("TASKCLUSTER_") {
                env::remove_var(key);
            }
        }
        guard
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct TempCredsTestCase {
        pub description: String,
        pub perm_creds: Credentials,
        pub seed: String,
        pub start: String,
        pub expiry: String,
        pub temp_creds_name: String,
        pub temp_creds_scopes: Vec<String>,
        pub expected_temp_creds: Credentials,
    }

    fn test_cred(tc: &TempCredsTestCase) {
        let start = chrono::DateTime::parse_from_rfc3339(&tc.start).unwrap();
        let expiry = chrono::DateTime::parse_from_rfc3339(&tc.expiry).unwrap();

        let mut temp_creds = tc
            .perm_creds
            .create_named_temp_creds(
                &tc.temp_creds_name,
                time::Duration::from_secs(3600),
                tc.temp_creds_scopes.clone(),
            )
            .unwrap();

        let mut cert: Certificate = serde_json::from_str(&temp_creds.certificate.unwrap()).unwrap();
        cert.seed = tc.seed.clone();
        temp_creds.access_token = gen_temp_access_token(&tc.perm_creds.access_token, &cert.seed);
        cert.start = start.timestamp_millis();
        cert.expiry = expiry.timestamp_millis();
        cert.sign(&tc.perm_creds.access_token, &temp_creds.client_id);
        temp_creds.certificate = Some(serde_json::to_string(&cert).unwrap());
        assert_eq!(temp_creds, tc.expected_temp_creds);
    }

    #[test]
    fn test_static_temp_creds() {
        let mut test_case_path = path::PathBuf::from(file!()).parent().unwrap().to_path_buf();
        test_case_path.push("../../client-go/testcases.json");
        let tests = fs::read_to_string(test_case_path).unwrap();
        let test_cases: Vec<TempCredsTestCase> = serde_json::from_str(&tests).unwrap();

        for tc in &test_cases {
            test_cred(&tc);
        }
    }

    #[test]
    fn test_new_with_scopes() {
        let creds = Credentials::new_with_scopes("a-client", "a-token", vec!["scope1", "scope2"]);
        assert_eq!(creds.client_id, "a-client");
        assert_eq!(creds.access_token, "a-token");
        assert_eq!(creds.certificate, None);
        assert_eq!(creds.scopes, Some(vec!["scope1".into(), "scope2".into()]));
    }

    #[test]
    fn test_new() {
        let creds = Credentials::new("a-client", "a-token");
        assert_eq!(creds.client_id, "a-client");
        assert_eq!(creds.access_token, "a-token");
        assert_eq!(creds.certificate, None);
        assert_eq!(creds.scopes, None);
    }

    #[test]
    fn test_from_env() {
        let _guard = clear_env();
        env::set_var("TASKCLUSTER_CLIENT_ID", "a-client");
        env::set_var("TASKCLUSTER_ACCESS_TOKEN", "a-token");
        let creds = Credentials::from_env().unwrap();
        assert_eq!(creds.client_id, "a-client");
        assert_eq!(creds.access_token, "a-token");
        assert_eq!(creds.certificate, None);
        assert_eq!(creds.scopes, None);
    }

    #[test]
    fn test_from_env_missing() {
        let _guard = clear_env();
        env::set_var("TASKCLUSTER_CLIENT_ID", "a-client");
        // (no access token)
        assert!(Credentials::from_env().is_err());
    }

    #[test]
    fn test_from_env_cert() {
        let _guard = clear_env();
        env::set_var("TASKCLUSTER_CLIENT_ID", "a-client");
        env::set_var("TASKCLUSTER_ACCESS_TOKEN", "a-token");
        env::set_var("TASKCLUSTER_CERTIFICATE", "cert");
        let creds = Credentials::from_env().unwrap();
        assert_eq!(creds.client_id, "a-client");
        assert_eq!(creds.access_token, "a-token");
        assert_eq!(creds.certificate, Some("cert".into()));
        assert_eq!(creds.scopes, None);
    }
}
