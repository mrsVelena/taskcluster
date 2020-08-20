use crate::Credentials;
use async_std::task;
use backoff::backoff::Backoff;
use backoff::ExponentialBackoff;
use failure::{format_err, Error, ResultExt};
use hawk;
use reqwest;
use reqwest::header::HeaderValue;
use std::borrow::Borrow;
use std::iter::IntoIterator;
use std::str::FromStr;
use std::time::Duration;

#[allow(non_upper_case_globals)]
pub(crate) const NoScopes: Option<Vec<String>> = None;

#[allow(non_upper_case_globals)]
pub(crate) const NoBody: Option<&str> = None;

#[allow(non_upper_case_globals)]
pub(crate) const NoQuery: Option<Vec<(String, String)>> = None;

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

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::{mock, server_url, Matcher};
    use serde_json::json;
    use tokio;

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
