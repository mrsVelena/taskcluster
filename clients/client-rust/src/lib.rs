//! A client library for accessing Taskcluster APIs.
//!
//! # Examples:
//!
//! High-level access via the generated service-specific client types:
//!
//! ```
//! # use httptest::{matchers::*, responders::*, Expectation, Server};
//! # use tokio;
//! # use failure::Fallible;
//! # use serde_json::json;
//! # #[tokio::main]
//! # async fn main() -> Fallible<()> {
//! # let server = Server::run();
//! # server.expect(
//! #    Expectation::matching(request::method_path("GET", "/api/auth/v1/clients/static%2Ftaskcluster%2Froot"))
//! #   .respond_with(
//! #       status_code(200)
//! #       .append_header("Content-Type", "application/json")
//! #       .body("{\"clientId\": \"static/taskcluster/root\"}"))
//! # );
//! # let root_url = format!("http://{}", server.addr());
//! use taskcluster::Auth;
//! let auth = Auth::new(&root_url, None)?;
//! let resp = auth.client("static/taskcluster/root").await?;
//! assert_eq!(resp, json!({"clientId": "static/taskcluster/root"}));
//! Ok(())
//! # }
//! ```
//!
//! Low-level access via the [Client](struct.Client.html) type:
//!
//! ```
//! # use httptest::{matchers::*, responders::*, Expectation, Server};
//! # use tokio;
//! # use std::env;
//! # use failure::Fallible;
//! # #[tokio::main]
//! # async fn main() -> Fallible<()> {
//! # let server = Server::run();
//! # server.expect(
//! #    Expectation::matching(request::method_path("POST", "/api/queue/v1/task/G08bnnBuR6yDhDLJkJ6KiA/cancel"))
//! #   .respond_with(status_code(200))
//! # );
//! # let root_url = format!("http://{}", server.addr());
//! use taskcluster::{Client, Credentials};
//! # env::set_var("TASKCLUSTER_CLIENT_ID", "a-client");
//! # env::set_var("TASKCLUSTER_ACCESS_TOKEN", "a-token");
//! let creds = Credentials::from_env()?;
//! let client = Client::new(&root_url, "queue", "v1", Some(creds))?;
//! let resp = client.request("POST", "task/G08bnnBuR6yDhDLJkJ6KiA/cancel", None, None).await?;
//! assert!(resp.status().is_success());
//! Ok(())
//! # }
//! ```

mod client;
mod credentials;
mod generated;
mod util;

pub use client::Client;
pub use credentials::Credentials;
pub use generated::*;
