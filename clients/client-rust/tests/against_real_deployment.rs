use failure::Fallible;
use serde_json::json;
use std::env;
use taskcluster::Auth;
use tokio;

/// Return the TASKCLUSTER_ROOT_URL, or None if the test should be skipped,
/// or panic if the NO_TEST_SKIP is set and the env var is not.
fn get_root_url() -> Option<String> {
    match env::var("TASKCLUSTER_ROOT_URL") {
        Ok(v) => Some(v),
        Err(_) => match env::var("NO_TEST_SKIP") {
            Ok(_) => panic!("NO_TEST_SKIP is set bu TASKCLUSTER_ROOT_URL is not!"),
            Err(_) => None,
        },
    }
}

#[tokio::test]
async fn test_auth_ping() -> Fallible<()> {
    if let Some(root_url) = get_root_url() {
        let auth = Auth::new(&root_url, None, None)?;
        auth.ping().await?;
    }
    Ok(())
}

/// Test that a 404 is treated as an error
#[tokio::test]
async fn test_no_such_client() -> Fallible<()> {
    // XXX NOTES:
    //  - other clients treat 4xx as error, so we should, too
    //    - 2xx all treated the same?
    //    - what about 3xx?
    //  - return reqwest::Error if possible so status is easy for callers to inspect
    //    - otherwise use a custom error type that can return this
    //      - but this is hard because reqwest::Error isn't Clone so Failure doesn't like it
    //      - ..so maybe a custom error that parses reqwest::Error in that case
    if let Some(root_url) = get_root_url() {
        let auth = Auth::new(&root_url, None, None)?;
        let res = auth.client("no/such/client/exists").await;
        // TODO: verify that this is a 404
        assert!(res.is_err());
    }
    Ok(())
}

/// Test a call with a query
#[tokio::test]
async fn test_auth_list_clients_paginated() -> Fallible<()> {
    if let Some(root_url) = get_root_url() {
        let auth = Auth::new(&root_url, None, None)?;
        let mut continuation_token: Option<String> = None;
        let limit = Some("2");
        let mut saw_root = false;

        loop {
            let res = auth
                .listClients(None, continuation_token.as_deref(), limit)
                .await?;
            for client in res.get("clients").unwrap().as_array().unwrap() {
                println!("{:?}", client);
                if client.get("clientId").unwrap().as_str().unwrap() == "static/taskcluster/root" {
                    saw_root = true;
                }
            }
            if let Some(v) = res.get("continuationToken") {
                continuation_token = Some(v.as_str().unwrap().to_owned());
            } else {
                break;
            }
        }
        // the root clientId should exist in any deployment.
        assert!(saw_root);
    }

    Ok(())
}

/// Test an un-authenticated call with input and output bodies
#[tokio::test]
async fn test_auth_expand_scopes() -> Fallible<()> {
    if let Some(root_url) = get_root_url() {
        let auth = Auth::new(&root_url, None, None)?;
        let mut saw_scope = false;

        let res = auth
            .expandScopes(&json!({"scopes": ["assume:abc"]}))
            .await?;
        for scope in res.get("scopes").unwrap().as_array().unwrap() {
            println!("{:?}", scope);
            if scope.as_str().unwrap() == "assume:abc" {
                saw_scope = true;
            }
        }
        // expansion always includes the input scopes, so this should exist
        assert!(saw_scope);
    }

    Ok(())
}
