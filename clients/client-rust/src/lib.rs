/*!
# Taskcluster Client for Rust

For a general guide to using Taskcluster clients, see [Calling Taskcluster
APIs](https://docs.taskcluster.net/docs/manual/using/api).

# Usage

## Setup

Before calling an API end-point, you'll need to create a client instance.  There is a struct for
each service, e.g., `Queue` and `Auth`.  Each has a `new` associated function that takes the same
arguments, described below.  Many Tascluster API methods can be called without credentials, while
others (those with associated scopes) require credentials.

In any case, you must at least supply a root URL to identify the Taskcluster deployment to which the API calls should be directed.

Here is a simple setup and use of an un-authenticated client:

```
# use httptest::{matchers::*, responders::*, Expectation, Server};
# use tokio;
# use failure::Fallible;
# use serde_json::json;
# #[tokio::main]
# async fn main() -> Fallible<()> {
# let server = Server::run();
# server.expect(
#    Expectation::matching(request::method_path("GET", "/api/auth/v1/clients/static%2Ftaskcluster%2Froot"))
#   .respond_with(
#       status_code(200)
#       .append_header("Content-Type", "application/json")
#       .body("{\"clientId\": \"static/taskcluster/root\"}"))
# );
# let root_url = format!("http://{}", server.addr());
use taskcluster::Auth;
let auth = Auth::new(&root_url, None)?;
let resp = auth.client("static/taskcluster/root").await?;
assert_eq!(resp, json!({"clientId": "static/taskcluster/root"}));
Ok(())
# }
```

Here is an example with credentials provided, in this case via the [standard environment variables](https://docs.taskcluster.net/docs/manual/design/env-vars).

```
# use httptest::{matchers::*, responders::*, Expectation, Server};
# use tokio;
use std::env;
# use failure::Fallible;
# #[tokio::main]
# async fn main() -> Fallible<()> {
# let server = Server::run();
# server.expect(
#    Expectation::matching(request::method_path("POST", "/api/queue/v1/task/G08bnnBuR6yDhDLJkJ6KiA/cancel"))
#   .respond_with(
#       status_code(200)
#       .append_header("Content-Type", "application/json")
#       .body("{\"status\": \"...\"}"))
# );
# env::set_var("TASKCLUSTER_ROOT_URL", format!("http://{}", server.addr()));
# env::set_var("TASKCLUSTER_CLIENT_ID", "a-client");
# env::set_var("TASKCLUSTER_ACCESS_TOKEN", "a-token");
use taskcluster::{Queue, Credentials};
let creds = Credentials::from_env()?;
let root_url = env::var("TASKCLUSTER_ROOT_URL").unwrap();
let client = Queue::new(&root_url, Some(creds))?;
let res = client.cancelTask("G08bnnBuR6yDhDLJkJ6KiA").await?;
println!("{}", res.get("status").unwrap());
Ok(())
# }
```

### Authorized Scopes

If you wish to perform requests on behalf of a third-party that has smaller set
of scopes than you do, you can specify [which scopes your request should be
allowed to
use](https://docs.taskcluster.net/docs/manual/design/apis/hawk/authorized-scopes).

These "authorized scopes" are in the `scopes` property of the Credentials struct,
and can be set directly or using the `new_with_scopes` associated function:

```
use taskcluster::Credentials;
let _creds = Credentials::new_with_scopes(
    "my/client/id",
    "RcFCn3D4SIeTh7T4zSLzZALsflI8-jSoiYBmigZkDs2A",
    vec!["some-scope", "another-scope"]);
```

```
# use std::env;
# env::set_var("TASKCLUSTER_CLIENT_ID", "a-client");
# env::set_var("TASKCLUSTER_ACCESS_TOKEN", "a-token");
use taskcluster::Credentials;
let mut creds = Credentials::from_env().unwrap();
creds.scopes = Some(vec!["some-scope".into()]);
```

## Calling API Methods

API methods are available as methods on the corresponding client object.  They are capitalized in
snakeCase (e.g., `createTask`) to match the Taskcluster documentation.

Each method takes arguments in the following order, where appropriate to the method:
 * Positional arguments (strings interpolated into the URL)
 * Request body (payload)
 * URL query arguments

The payload comes in the form of a `serde_json::Value`, the contents of which should match the API
method's input schema.  URL query arguments are all optional.

For example, the following lists all Auth clients:

```
# // note: pagination is more thoroughly tested in `tests/against_real_deployment.rs`
# use httptest::{matchers::*, responders::*, Expectation, Server};
# use tokio;
# use std::env;
# use failure::Fallible;
# #[tokio::main]
# async fn main() -> Fallible<()> {
# let server = Server::run();
# server.expect(
#    Expectation::matching(request::method_path("GET", "/api/auth/v1/clients/"))
#   .respond_with(
#       status_code(200)
#       .append_header("Content-Type", "application/json")
#       .body("{\"clients\": []}"))
# );
# let root_url = format!("http://{}", server.addr());
use taskcluster::{Auth, Credentials};
let auth = Auth::new(&root_url, None)?;
let mut continuation_token: Option<String> = None;
let limit = Some("10");

loop {
    let res = auth
        .listClients(None, continuation_token.as_deref(), limit)
        .await?;
    for client in res.get("clients").unwrap().as_array().unwrap() {
        println!("{:?}", client);
    }
    if let Some(v) = res.get("continuationToken") {
        continuation_token = Some(v.as_str().unwrap().to_owned());
    } else {
        break;
    }
}
# Ok(())
# }
```

### Low-Level Access

Instead of using the high-level methods, it is also possible to call API methods directly by path:

```
# use httptest::{matchers::*, responders::*, Expectation, Server};
# use tokio;
use std::env;
# use failure::Fallible;
# #[tokio::main]
# async fn main() -> Fallible<()> {
# let server = Server::run();
# server.expect(
#    Expectation::matching(request::method_path("POST", "/api/queue/v1/task/G08bnnBuR6yDhDLJkJ6KiA/cancel"))
#   .respond_with(status_code(200))
# );
# env::set_var("TASKCLUSTER_ROOT_URL", format!("http://{}", server.addr()));
# env::set_var("TASKCLUSTER_CLIENT_ID", "a-client");
# env::set_var("TASKCLUSTER_ACCESS_TOKEN", "a-token");
use taskcluster::{Client, Credentials};
let creds = Credentials::from_env()?;
let root_url = env::var("TASKCLUSTER_ROOT_URL").unwrap();
let client = Client::new(&root_url, "queue", "v1", Some(creds))?;
let resp = client.request("POST", "task/G08bnnBuR6yDhDLJkJ6KiA/cancel", None, None).await?;
assert!(resp.status().is_success());
Ok(())
# }
```

## Generating URLs

TBD

## Generating SlugIDs

Use the [slugid](https://crates.io/crates/slugid) crate to create slugIds (such as for a taskId).

*/

mod client;
mod credentials;
mod generated;
mod util;

pub use client::Client;
pub use credentials::Credentials;
pub use generated::*;
