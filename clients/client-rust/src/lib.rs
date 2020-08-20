//! A client library for accessing Taskcluster APIs.
//!
//! # Examples:
//!
//! Low-level access via the [Client](struct.Client.html) type:
//!
//! ```
//! # use mockito::*;
//! # use tokio;
//! # use std::env;
//! # use failure::Fallible;
//! # #[tokio::main]
//! # async fn main() -> Fallible<()> {
//! # let _mock = mock("POST", "/queue/v1/task/G08bnnBuR6yDhDLJkJ6KiA/cancel")
//! #   .with_status(200)
//! #   .create();
//! # let rootUrl = server_url();
//! use taskcluster::{Client, Credentials, NO_QUERY, NO_BODY};
//! # env::set_var("TASKCLUSTER_CLIENT_ID", "a-client");
//! # env::set_var("TASKCLUSTER_ACCESS_TOKEN", "a-token");
//! let creds = Credentials::from_env()?;
//! let client = Client::new(&rootUrl, "queue", "v1", Some(creds))?;
//! let resp = client.request("POST", "task/G08bnnBuR6yDhDLJkJ6KiA/cancel", NO_QUERY, NO_BODY).await?;
//! assert!(resp.status().is_success());
//! Ok(())
//! # }
//! ```

mod client;
mod credentials;

pub use client::{Client, NO_BODY, NO_QUERY};
pub use credentials::Credentials;
