use axum::{
    body::Bytes,
    http::{HeaderMap, StatusCode, Uri},
    response::Redirect,
    routing::{get, post},
    Router,
};
use bb8_redis::RedisConnectionManager;
use hmac::Hmac;
use once_cell::sync::Lazy;
use serde_json::Value;
use sha2::Sha256;
use std::{env, net::SocketAddr};
use tower_http::{limit::RequestBodyLimitLayer, trace::TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

type HmacSha256 = Hmac<Sha256>;

static WEBHOOK_SECRET: Lazy<Vec<u8>> = Lazy::new(|| {
    let secret = env::var("WEBHOOK_SECRET").unwrap();
    secret.trim().as_bytes().to_vec()
});

#[tokio::main]
async fn main() {
    println!("Hello, world!");

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "test_github_app=debug,tower_http=debug,axum::rejection=trace".into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let manager = RedisConnectionManager::new(env::var("REDIS_URL").unwrap()).unwrap();
    let pool = bb8::Pool::builder().build(manager).await.unwrap();

    let app = Router::new()
        .route("/health/ready", get(|| async { "Ready!".to_string() }))
        .route("/", get(redirect))
        .route(
            format!("/webhooks/{}", env::var("WEBHOOK_SLUG").unwrap()).as_str(),
            post(webhook),
        )
        .fallback(error404)
        .layer(RequestBodyLimitLayer::new(10240))
        .layer(TraceLayer::new_for_http())
        .with_state(pool);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn webhook(headers: HeaderMap, body: Bytes) -> Result<(), StatusCode> {
    dbg!(&headers); // TODO: Remove!
    dbg!(&body);

    let mut mac = {
        use hmac::digest::KeyInit;

        HmacSha256::new_from_slice(&WEBHOOK_SECRET).map_err(|_| StatusCode::BAD_REQUEST)?
    };
    {
        use hmac::Mac;

        mac.update(&body);

        match headers.get("x-hub-signature-256") {
            None => return Err(StatusCode::NOT_FOUND),
            Some(val) => {
                let val = val.to_str().map_err(|_| StatusCode::BAD_REQUEST)?;
                let val = val.replace("sha256=", "");

                if mac.verify_slice(val.as_bytes()).is_ok() {
                    tracing::debug!("Webhook signature is wrong.");
                    return Err(StatusCode::NOT_FOUND);
                }
            }
        }
    }

    let payload: Value = serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    dbg!(&payload); // TODO: Remove!

    match payload.get("action") {
        None => Err(StatusCode::BAD_REQUEST),
        Some(Value::String(_)) => Ok(()),
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

async fn redirect() -> Redirect {
    Redirect::temporary("https://github.com/harmless-tech/test-github-app")
}

async fn error404(uri: Uri) -> (StatusCode, String) {
    (StatusCode::NOT_FOUND, format!("Not found: {uri}"))
}
