use crate::util;
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
pub struct Certificate {
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

fn collect_scopes<R: FromIterator<String>>(
    scopes: Option<impl IntoIterator<Item = impl AsRef<str>>>,
) -> Option<R> {
    scopes.map(|scopes| scopes.into_iter().map(|s| s.as_ref().to_string()).collect())
}

impl Credentials {
    /// Create a new Credentials object from environment variables:
    /// TASKCLUSTER_CLIENT_ID
    /// TASKCLUSTER_ACCESS_TOKEN
    /// TASKCLUSTER_CERTIFICATE (optional)
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

    /// Create a new Credentials object with the given scopes. The scopes parameter, when not None,
    /// must be a collection in which items implements AsRef<str> (&str and String are such types).
    ///
    /// Examples:
    ///     use taskcluster::Credentials;
    ///     let _ = Credentials::new("my_client_id", "my_access_token", Some(&["scope1", "scope2", "scope3"]));
    ///
    ///     use taskcluster::Credentials;
    ///     let scopes: Vec<_> = vec!["scope1", "scope2", "scope3"].into_iter().collect();
    ///     let _ = Credentials::new("my_client_id", "my_access_token", Some(scopes));
    pub fn new(
        client_id: &str,
        access_token: &str,
        scopes: Option<impl IntoIterator<Item = impl AsRef<str>>>,
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
        scopes: Option<impl IntoIterator<Item = impl AsRef<str>>>,
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

        let temp_access_token = util::gen_temp_access_token(&self.access_token, &cert.seed);

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
        scopes: Option<impl IntoIterator<Item = impl AsRef<str>>>,
    ) -> Result<Credentials, Error> {
        self.create_named_temp_creds("", duration, scopes)
    }

    pub fn certificate(&self) -> Option<Certificate> {
        match self.certificate {
            Some(ref cert) => Some(serde_json::from_str(cert).unwrap()),
            None => None,
        }
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
