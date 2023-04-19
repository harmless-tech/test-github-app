use crate::{
    secure::WEBHOOK_MAC,
    states,
    states::{AppState, ConnectionPool, IDENT_APP_ID, IDENT_TOKEN_URL},
};
use axum::{
    body::{Body, Bytes},
    extract::State,
    http::HeaderMap,
    routing::post,
    Router,
};
use bb8_redis::redis::cmd;

use serde_json::{Map, Value};
use std::env;
use tower_http::{limit::RequestBodyLimitLayer, timeout::ResponseBodyTimeoutLayer};

pub async fn get_routes() -> Router<AppState, Body> {
    let app_state = states::build_app_state().await;
    Router::new()
        .route(
            format!("/{}", env::var("WEBHOOK_SLUG").unwrap()).as_str(),
            post(webhook),
        )
        .layer(RequestBodyLimitLayer::new(30000000))
        .layer(ResponseBodyTimeoutLayer::new(std::time::Duration::new(
            60, 0,
        )))
        .with_state(app_state)
}

async fn webhook(
    State(pool): State<ConnectionPool>,
    State(app): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(), ()> {
    let event = match headers.get("x-github-event") {
        None => return Err(()),
        Some(val) => val.to_str().unwrap(),
    };

    let mut mac = WEBHOOK_MAC.clone();
    {
        use hmac::Mac;

        mac.update(&body);
        match headers.get("x-hub-signature-256") {
            None => return Err(()),
            Some(val) => {
                let val = val.to_str().map_err(|_| ())?;
                let val = val.replace("sha256=", "");
                let val = hex::decode(val).expect("Header does not contain sha256 string");

                if mac.verify_slice(&val).is_err() {
                    tracing::debug!("Webhook signature is wrong.");
                    return Err(());
                }
            }
        }
    }

    let payload: Value = serde_json::from_slice(&body).map_err(|_| ())?;

    match event {
        "installation" => {
            tokio::spawn(async move { check_app_id(&app, &pool, &payload).await });
        }
        "issue_comment" => {
            tokio::spawn(async move {
                if payload["action"].as_str().unwrap().eq("created") {
                    let issue = payload["issue"].as_object().unwrap();
                    let comment = payload["comment"].as_object().unwrap();
                    if issue.contains_key("pull_request") {
                        tracing::debug!("Found issue comment created with pull request.");
                        if issue["state"].as_str().unwrap().eq("open")
                            && author_association_allowed(
                                comment["author_association"].as_str().unwrap(),
                            )
                        {
                            // Parse comment for workflow name and possible args
                            let contents = comment["body"].as_str().unwrap();
                            if !contents.starts_with("!harmful ") {
                                return;
                            }

                            let contents = contents[9..].trim();
                            if contents.is_empty() {
                                return;
                            }

                            let i = contents.split_once(' ');
                            let cmd_info = match i {
                                None => (contents, None),
                                Some((s1, s2)) => {
                                    let v: Value =
                                        serde_json::from_str(s2).expect("arg received is not json");
                                    if !v.is_object() {
                                        return;
                                    }
                                    (s1, Some(v))
                                }
                            };

                            // Get pull request info
                            let pull_url = issue["pull_request"]
                                .as_object()
                                .unwrap()
                                .get("url")
                                .unwrap()
                                .as_str()
                                .unwrap();
                            let mut token = app.access_token.write().await;
                            let pull_request = token.get(&app.data, pull_url).await.await;

                            match pull_request {
                                Ok(res) => match res.status() {
                                    reqwest::StatusCode::OK => {
                                        let pull_json: Value = res
                                            .json()
                                            .await
                                            .expect("Did not receive json from pull api request.");
                                        let repo_url = pull_json["base"]
                                            .as_object()
                                            .unwrap()
                                            .get("repo")
                                            .unwrap()
                                            .as_object()
                                            .unwrap()
                                            .get("url")
                                            .unwrap()
                                            .as_str()
                                            .unwrap();
                                        let pull_ref = pull_json["head"]
                                            .as_object()
                                            .unwrap()
                                            .get("ref")
                                            .unwrap()
                                            .as_str()
                                            .unwrap();

                                        let url = format!(
                                            "{repo_url}/actions/workflows/{}.yml/dispatches",
                                            cmd_info.0
                                        );

                                        let mut json_map = Map::new();
                                        json_map.insert(
                                            "ref".to_string(),
                                            Value::String(pull_ref.to_string()),
                                        );
                                        if let Some(v) = cmd_info.1 {
                                            json_map.insert("inputs".to_string(), v);
                                        }
                                        let json = Value::Object(json_map);

                                        let request =
                                            token.post_json(&app.data, &url, &json).await.await;
                                        match request {
                                            Ok(res) => match res.status() {
                                                reqwest::StatusCode::NO_CONTENT => {
                                                    tracing::info!(
                                                        "Started workflow {} with {json}",
                                                        cmd_info.0
                                                    );

                                                    // React
                                                    let react_url = payload["comment"]
                                                        .as_object()
                                                        .unwrap()
                                                        .get("reactions")
                                                        .unwrap()
                                                        .as_object()
                                                        .unwrap()
                                                        .get("url")
                                                        .unwrap()
                                                        .as_str()
                                                        .unwrap();

                                                    let mut json_map = Map::new();
                                                    json_map.insert(
                                                        "content".to_string(),
                                                        Value::String("rocket".to_string()),
                                                    );
                                                    let json = Value::Object(json_map);

                                                    let r = token
                                                        .post_json(&app.data, react_url, &json)
                                                        .await
                                                        .await
                                                        .expect("Bad request error (reactions)");
                                                    tracing::debug!("Added reaction for workflow {} with {json} (status code {})", cmd_info.0, r.status());
                                                }
                                                err => tracing::error!(
                                                    "Pull request api error '{url}': {err}"
                                                ),
                                            },
                                            Err(err) => tracing::error!(
                                                "Pull request api error '{url}': {err}"
                                            ),
                                        }
                                    }
                                    err => tracing::error!(
                                        "Pull request api error '{pull_url}': status code {err}"
                                    ),
                                },
                                Err(err) => {
                                    tracing::error!("Pull request api error '{pull_url}': {err}")
                                }
                            }
                        }
                    }
                }
            });
        }
        "workflow_run" => {
            tokio::spawn(async move {
                let pool = pool.unwrap();
                match payload["action"].as_str().unwrap() {
                    "requested" => {
                        let workflow_run = payload["workflow_run"].as_object().unwrap();
                        if workflow_run["actor"]
                            .as_object()
                            .unwrap()
                            .get("id")
                            .unwrap()
                            .as_u64()
                            .unwrap()
                            == 130938523
                        {
                            let id = workflow_run["id"].as_u64().unwrap();
                            let name = workflow_run["display_title"].as_str().unwrap();
                            let head_sha = workflow_run["head_sha"].as_str().unwrap();
                            let details_url = workflow_run["html_url"].as_str().unwrap();
                            let started_at = workflow_run["run_started_at"].as_str().unwrap();
                            let status = workflow_run["status"].as_str().unwrap();

                            let url = workflow_run["head_repository"]
                                .as_object()
                                .unwrap()
                                .get("url")
                                .unwrap()
                                .as_str()
                                .unwrap();
                            let url = format!("{url}/check-runs");

                            let mut json_map = Map::new();
                            json_map.insert("name".to_string(), Value::String(name.to_string()));
                            json_map.insert(
                                "head_sha".to_string(),
                                Value::String(head_sha.to_string()),
                            );
                            json_map.insert(
                                "details_url".to_string(),
                                Value::String(details_url.to_string()),
                            );
                            json_map.insert(
                                "started_at".to_string(),
                                Value::String(started_at.to_string()),
                            );
                            json_map
                                .insert("status".to_string(), Value::String(status.to_string()));
                            let json = Value::Object(json_map);

                            let mut token = app.access_token.write().await;
                            let request = token.post_json(&app.data, &url, &json).await.await;
                            match request {
                                Ok(res) => match res.status() {
                                    reqwest::StatusCode::CREATED => {
                                        let cr_json: Value = res.json().await.expect(
                                            "Did not receive json from cr create api request.",
                                        );
                                        let cr_id = cr_json["id"].as_u64().unwrap();
                                        tracing::info!(
                                            "Created check run {cr_id} for workflow {id}"
                                        );

                                        let mut conn1 = pool.get().await.unwrap();
                                        let reply: String = cmd("SET")
                                            .arg(format!("workflow_cr.{id}"))
                                            .arg(cr_id)
                                            .query_async(&mut *conn1)
                                            .await
                                            .unwrap();
                                        tracing::debug!("Set workflow cr {id} to {cr_id}: {reply}");

                                        let mut conn2 = pool.get().await.unwrap();
                                        let _: usize = cmd("EXPIRE")
                                            .arg(format!("workflow_cr.{id}"))
                                            .arg(21600)
                                            .query_async(&mut *conn2)
                                            .await
                                            .unwrap();
                                    }
                                    err => tracing::error!("Check run api error '{url}': {err}"),
                                },
                                Err(err) => tracing::error!("Check run api error '{url}': {err}"),
                            }
                        }
                    }
                    "in_progress" => {
                        let workflow_run = payload["workflow_run"].as_object().unwrap();
                        if workflow_run["actor"]
                            .as_object()
                            .unwrap()
                            .get("id")
                            .unwrap()
                            .as_u64()
                            .unwrap()
                            == 130938523
                        {
                            let id = workflow_run["id"].as_u64().unwrap();
                            let status = workflow_run["status"].as_str().unwrap();

                            let mut conn = pool.get().await.unwrap();
                            let reply: Option<u64> = cmd("GET")
                                .arg(format!("workflow_cr.{id}"))
                                .query_async(&mut *conn)
                                .await
                                .unwrap();
                            tracing::debug!("Get workflow cr {id}: {reply:?}");
                            let cr_id = match reply {
                                None => return,
                                Some(cr) => cr,
                            };

                            let url = workflow_run["head_repository"]
                                .as_object()
                                .unwrap()
                                .get("url")
                                .unwrap()
                                .as_str()
                                .unwrap();
                            let url = format!("{url}/check-runs/{cr_id}");

                            let mut json_map = Map::new();
                            json_map
                                .insert("status".to_string(), Value::String(status.to_string()));
                            let json = Value::Object(json_map);

                            let mut token = app.access_token.write().await;
                            let request = token.patch_json(&app.data, &url, &json).await.await;
                            match request {
                                Ok(res) => match res.status() {
                                    reqwest::StatusCode::OK => tracing::info!("Updated check run {cr_id} to in_progress for workflow {id}"),
                                    err => tracing::error!("Check run api error '{url}': {err}")
                                }
                                Err(err) => tracing::error!("Check run api error '{url}': {err}"),
                            }
                        }
                    }
                    "completed" => {
                        let workflow_run = payload["workflow_run"].as_object().unwrap();
                        if workflow_run["actor"]
                            .as_object()
                            .unwrap()
                            .get("id")
                            .unwrap()
                            .as_u64()
                            .unwrap()
                            == 130938523
                        {
                            let id = workflow_run["id"].as_u64().unwrap();
                            let status = workflow_run["status"].as_str().unwrap();
                            let conclusion = workflow_run["conclusion"].as_str().unwrap();
                            let completed_at = workflow_run["updated_at"].as_str().unwrap();

                            let mut conn = pool.get().await.unwrap();
                            let reply: Option<u64> = cmd("GET")
                                .arg(format!("workflow_cr.{id}"))
                                .query_async(&mut *conn)
                                .await
                                .unwrap();
                            tracing::debug!("Get workflow cr {id}: {reply:?}");
                            let cr_id = match reply {
                                None => return,
                                Some(cr) => cr,
                            };

                            let url = workflow_run["head_repository"]
                                .as_object()
                                .unwrap()
                                .get("url")
                                .unwrap()
                                .as_str()
                                .unwrap();
                            let url = format!("{url}/check-runs/{cr_id}");

                            let mut json_map = Map::new();
                            json_map
                                .insert("status".to_string(), Value::String(status.to_string()));
                            json_map.insert(
                                "conclusion".to_string(),
                                Value::String(conclusion.to_string()),
                            );
                            json_map.insert(
                                "completed_at".to_string(),
                                Value::String(completed_at.to_string()),
                            );
                            let json = Value::Object(json_map);

                            let mut token = app.access_token.write().await;
                            let request = token.patch_json(&app.data, &url, &json).await.await;
                            match request {
                                Ok(res) => match res.status() {
                                    reqwest::StatusCode::OK => {
                                        tracing::info!("Updated check run {cr_id} to completed for workflow {id}");

                                        let mut conn = pool.get().await.unwrap();
                                        let _: usize = cmd("Del")
                                            .arg(format!("workflow_cr.{id}"))
                                            .query_async(&mut *conn)
                                            .await
                                            .unwrap();
                                    }
                                    err => tracing::error!("Check run api error '{url}': {err}"),
                                },
                                Err(err) => tracing::error!("Check run api error '{url}': {err}"),
                            }
                        }
                    }
                    _ => {}
                }
            });
        }
        _ => {
            tracing::info!("Cannot handle event '{event}', ignored.");
        }
    }

    Ok(())
}

fn author_association_allowed(association: &str) -> bool {
    matches!(association, "OWNER" | "MEMBER" | "COLLABORATOR")
}

async fn check_app_id(app: &AppState, pool: &ConnectionPool, payload: &Value) {
    let pool1 = pool.as_ref().unwrap().get();
    let pool2 = pool.as_ref().unwrap().get();

    let no_app_id = app.data.read().await.is_none();
    if no_app_id {
        let installation = payload["installation"]
            .as_object()
            .expect("Expected installation to be object");
        let app_id = installation[IDENT_APP_ID]
            .as_u64()
            .expect("Expected app_id to be a u64");
        let token_url = installation[IDENT_TOKEN_URL]
            .as_str()
            .expect("Expected app_id to be a u64");

        let mut conn1 = pool1.await.unwrap();
        let reply1: String = cmd("SET")
            .arg(IDENT_APP_ID)
            .arg(app_id)
            .query_async(&mut *conn1)
            .await
            .unwrap();
        tracing::debug!("APP_ID set persist: {reply1} to {app_id}");

        let mut conn2 = pool2.await.unwrap();
        let reply2: String = cmd("SET")
            .arg(IDENT_TOKEN_URL)
            .arg(token_url)
            .query_async(&mut *conn2)
            .await
            .unwrap();
        tracing::debug!("APP_TOKEN_URL set persist: {reply2} to {token_url}");

        let mut f = app.data.write().await;
        *f = Some((app_id, token_url.to_string()));
    }
}
