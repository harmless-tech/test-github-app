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

use serde_json::Value;
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
    #[cfg(debug_assertions)]
    dbg!(&headers);

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
    #[cfg(debug_assertions)]
    dbg!(&payload);

    // TODO: Handlers!!!

    match event {
        "installation" => {
            check_app_id(&app, &pool, &payload).await;
        }
        "issue_comment" => {
            tokio::spawn(async move {
                let pull_req = payload["issue"]
                    .as_object()
                    .unwrap()
                    .contains_key("pull_request");

                tracing::debug!("CONTAINS PULL REQUEST: {pull_req}");

                //
                let mut token = app.access_token.write().await;

                let r = token
                    .post(&app.data, "https://harmless.tech")
                    .await
                    .unwrap()
                    .await
                    .unwrap()
                    .text()
                    .await
                    .unwrap();
                tracing::debug!("POST OUTPUT: {r}");
                //
            });

            // Check if open
            // Check author_association
            // Check if pull request
            // Call api with url
            // Get head->ref
            // Call workflow
            // React positive if success, otherwise negative
        }
        _ => {
            tracing::info!("Cannot handle event '{event}', ignored.");
        }
    }

    Ok(())
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