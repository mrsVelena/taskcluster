use crate::slugid;
use async_std::task;
use backoff::backoff::Backoff;
use backoff::ExponentialBackoff;
use base64;
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::sha2::Sha256;
use failure::{err_msg, format_err, Error, ResultExt};
use hawk;
use reqwest;
use reqwest::header::HeaderValue;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json;
use std::borrow::Borrow;
use std::env;
use std::iter::{FromIterator, IntoIterator, Iterator};
use std::str::FromStr;
use std::time::{Duration, SystemTime};

#[allow(non_upper_case_globals)]
pub(crate) const NoScopes: Option<Vec<String>> = None;

#[allow(non_upper_case_globals)]
pub(crate) const NoBody: Option<&str> = None;

#[allow(non_upper_case_globals)]
pub(crate) const NoQuery: Option<Vec<(String, String)>> = None;

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
    certificate: Option<String>,
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

/// Client is the entry point into all the functionality in this package. It
/// contains authentication credentials, and a service endpoint, which are
/// required for all HTTP operations.
#[derive(Debug, Clone)]
pub(crate) struct Client {
    /// The credentials associated with this client. If authenticated request is made if None
    pub credentials: Option<Credentials>,
    /// The request URL
    pub url: reqwest::Url,
    /// Request client
    client: reqwest::Client,
}

fn gen_temp_access_token(perm_access_token: &str, seed: &str) -> String {
    let mut hash = Hmac::new(Sha256::new(), perm_access_token.as_bytes());
    hash.input(seed.as_bytes());
    base64::encode_config(hash.result().code(), base64::URL_SAFE_NO_PAD)
}

fn collect_scopes<R: FromIterator<String>>(
    scopes: Option<impl IntoIterator<Item = impl AsRef<str>>>,
) -> Option<R> {
    scopes.map(|scopes| scopes.into_iter().map(|s| s.as_ref().to_string()).collect())
}

impl Client {
    /// Instatiate a new client for a taskcluster service.
    /// The root_url is the taskcluster deployment root url,
    /// service_name is the name of the service and version
    /// is the service version
    pub fn new<'b>(
        root_url: &str,
        service_name: &str,
        version: &str,
        credentials: Option<Credentials>,
    ) -> Result<Client, Error> {
        Ok(Client {
            credentials,
            url: reqwest::Url::parse(root_url)
                .context(root_url.to_owned())?
                .join(&format!("/{}/{}/", service_name, version))
                .context(format!("{} {}", service_name, version))?,
            client: reqwest::Client::new(),
        })
    }

    /// request is the underlying method that makes a raw API request,
    /// performing any json marshaling/unmarshaling of requests/responses.
    pub async fn request<'a, I, K, V, B>(
        &self,
        method: &str,
        path: &str,
        query: Option<I>,
        body: Option<B>,
    ) -> Result<reqwest::Response, Error>
    where
        I: IntoIterator,
        I::Item: Borrow<(K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
        B: serde::Serialize,
    {
        let mut backoff = ExponentialBackoff::default();
        backoff.max_elapsed_time = Some(Duration::from_secs(5));
        backoff.reset();

        let req = self.build_request(method, path, query, body)?;
        let url = req.url().as_str();

        let resp = loop {
            let req = req
                .try_clone()
                .ok_or(format_err!("Cannot clone the request {}", url))?;

            let result = self.exec_request(url, method, req).await;
            if result.is_ok() {
                break result;
            }

            match backoff.next_backoff() {
                Some(duration) => task::sleep(duration).await,
                None => break result,
            }
        }?;

        let status = resp.status();
        if status.is_success() {
            Ok(resp)
        } else {
            Err(format_err!(
                "Error executing request\nmethod: {}\nurl: {}\nstatus: {}({})\nresponse: \"{}\"",
                method,
                &url,
                status.canonical_reason().unwrap_or("Unknown error"),
                status.as_str(),
                resp.text()
                    .await
                    .unwrap_or_else(|err| format!("Cannot retrieve response body: {}", err)),
            ))
        }
    }

    async fn exec_request(
        &self,
        url: &str,
        method: &str,
        req: reqwest::Request,
    ) -> Result<reqwest::Response, Error> {
        let resp = self.client.execute(req).await.context(url.to_owned())?;

        let status = resp.status();
        if status.is_server_error() {
            Err(format_err!(
                "Error executing request\nmethod: {}\nrequest\nURL: {}\nstatus: {}({})\nresponse: \"{}\"",
                method,
                url,
                status.canonical_reason().unwrap_or("Unknown error"),
                status.as_str(),
                resp.text()
                    .await
                    .unwrap_or_else(|err| format!("Cannot retrieve response body: {}", err)),
            ))
        } else {
            Ok(resp)
        }
    }

    fn build_request<'b, I, K, V, B>(
        &self,
        method: &str,
        path: &str,
        query: Option<I>,
        body: Option<B>,
    ) -> Result<reqwest::Request, Error>
    where
        I: IntoIterator,
        I::Item: Borrow<(K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
        B: serde::Serialize,
    {
        let mut url = self.url.join(path).context(path.to_owned())?;

        if let Some(q) = query {
            url.query_pairs_mut().extend_pairs(q);
        }

        let meth = reqwest::Method::from_str(method).context(method.to_owned())?;

        let req = self.client.request(meth, url);

        let req = match body {
            Some(b) => req.json(&b),
            None => req,
        };

        let req = req
            .build()
            .context(method.to_owned())
            .context(path.to_owned())?;

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
            self.url.scheme()
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
    ///     use taskcluster::client;
    ///     let _ = client::Credentials::new("my_client_id", "my_access_token", Some(&["scope1", "scope2", "scope3"]));
    ///
    ///     use taskcluster::client;
    ///     let scopes: Vec<_> = vec!["scope1", "scope2", "scope3"].into_iter().collect();
    ///     let _ = client::Credentials::new("my_client_id", "my_access_token", Some(scopes));
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
    fn sign(&mut self, access_token: &str, temp_client_id: &str) {
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
    use mockito::{mock, server_url, Matcher};
    use serde::{Deserialize, Serialize};
    use serde_json::json;
    use std::fs;
    use std::path;
    use std::time;
    use tokio;

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
                Some(tc.temp_creds_scopes.clone()),
            )
            .unwrap();

        let mut cert = temp_creds.certificate().unwrap();
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

    #[tokio::test]
    async fn test_simple_request() -> Result<(), Error> {
        let _mock = mock("GET", "/queue/v1/ping").with_status(200).create();
        let server = server_url();

        let client = Client::new(&server, "queue", "v1", None)?;
        let resp = client.request("GET", "ping", NoQuery, NoBody).await?;
        assert!(resp.status().is_success());
        Ok(())
    }

    #[tokio::test]
    async fn test_query() -> Result<(), Error> {
        let _mock = mock("GET", "/queue/v1/test")
            .match_query(Matcher::UrlEncoded("taskcluster".into(), "test".into()))
            .match_query(Matcher::UrlEncoded("client".into(), "rust".into()))
            .with_status(200)
            .create();
        let server = server_url();

        let client = Client::new(&server, "queue", "v1", None)?;
        let resp = client
            .request(
                "GET",
                "test",
                Some(&[("taskcluster", "test"), ("client", "rust")]),
                NoBody,
            )
            .await?;
        assert!(resp.status().is_success());
        Ok(())
    }

    #[tokio::test]
    async fn test_body() -> Result<(), Error> {
        let body = json!({"hello": "world"});

        let _mock = mock("POST", "/queue/v1/test")
            .match_body(Matcher::Json(body.clone()))
            .with_status(200)
            .create();
        let server = server_url();

        let client = Client::new(&server, "queue", "v1", None)?;
        let resp = client.request("POST", "test", NoQuery, Some(body)).await?;
        assert!(resp.status().is_success());
        Ok(())
    }
}
