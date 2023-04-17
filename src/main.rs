use axum::{
    body::Bytes,
    extract::{FromRef, State},
    http::{HeaderMap, StatusCode, Uri},
    response::Redirect,
    routing::{get, post},
    Router,
};
use bb8::Pool;
use bb8_redis::{redis::cmd, RedisConnectionManager};
use hmac::Hmac;
use jsonwebtoken::EncodingKey;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use std::{
    env,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::RwLock;
use tower_http::{
    limit::RequestBodyLimitLayer, timeout::ResponseBodyTimeoutLayer, trace::TraceLayer,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

type ConnectionPool = Pool<RedisConnectionManager>;
type HmacSha256 = Hmac<Sha256>;

static WEBHOOK_SECRET: Lazy<Vec<u8>> = Lazy::new(|| {
    let secret = env::var("WEBHOOK_SECRET").unwrap();
    secret.trim().as_bytes().to_vec()
});

static GH_APP_KEY: Lazy<EncodingKey> = Lazy::new(|| {
    let secret = env::var("GH_APP_KEY").unwrap();
    EncodingKey::from_rsa_pem(secret.as_bytes()).expect("Failed to get RSA private key!")
});

#[derive(Debug, Clone)]
struct AppState {
    app_id: Arc<RwLock<Option<u64>>>,
    pool: ConnectionPool,
}
impl AppState {
    async fn new(pool: ConnectionPool) -> Self {
        let base = {
            let mut conn = pool.get().await.unwrap();
            let reply: Option<u64> = cmd("GET")
                .arg("app_id")
                .query_async(&mut *conn)
                .await
                .unwrap();
            tracing::debug!("APP_ID from persist: {reply:?}");
            reply
        };

        Self {
            app_id: Arc::new(RwLock::new(base)),
            pool,
        }
    }
}
impl FromRef<AppState> for ConnectionPool {
    fn from_ref(input: &AppState) -> Self {
        input.pool.clone()
    }
}

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

    let app_state = AppState::new(pool).await;

    let app = Router::new()
        .route("/health/ready", get(|| async { "Ready!".to_string() }))
        .route("/", get(redirect))
        .route(
            format!("/webhooks/{}", env::var("WEBHOOK_SLUG").unwrap()).as_str(),
            post(webhook),
        )
        .fallback(error404)
        .layer(RequestBodyLimitLayer::new(30000000))
        .layer(ResponseBodyTimeoutLayer::new(Duration::new(60, 0)))
        .layer(TraceLayer::new_for_http())
        .with_state(app_state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn webhook(
    State(pool): State<ConnectionPool>,
    State(app): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(), StatusCode> {
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

                // TODO: Use constant compare? Does it matter?
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
        None => panic!("GitHub payload is missing action!"),
        Some(Value::String(s)) => match s.as_str() {
            "created" | "new_permissions_accepted" | "unsuspend" => {
                let pool = pool.get();

                let no_app_id = app.app_id.read().await.is_none();
                if no_app_id {
                    let app_id = payload["installation"]
                        .as_object()
                        .expect("Expected installation to be object")
                        .get("app_id")
                        .expect("Expected installation to have key app_id")
                        .as_u64()
                        .expect("Expected app_id to be a u64");

                    let mut conn = pool.await.unwrap();
                    let reply: String = cmd("SET")
                        .arg("app_id")
                        .arg(app_id)
                        .query_async(&mut *conn)
                        .await
                        .unwrap();
                    tracing::debug!("APP_ID set persist: {reply} to {app_id}");

                    let mut f = app.app_id.write().await;
                    *f = Some(app_id);
                }

                Ok(())
            }
            _ => Err(StatusCode::ACCEPTED),
        },
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    iat: u64, // Issued at (as UTC timestamp)
    exp: u64, // Expiration time (as UTC timestamp)
    iss: u64, // Issuer
}

fn gen_jwt(iss: u64) -> String {
    use jsonwebtoken::{encode, Algorithm, Header};

    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("TIME_ERR")
        .as_secs();
    encode(
        &Header::new(Algorithm::RS256),
        &Claims {
            iat: time - 60,
            exp: time + (60 * 5),
            iss,
        },
        &GH_APP_KEY,
    )
    .expect("Could not encode JWT.")
}

async fn redirect() -> Redirect {
    Redirect::temporary("https://github.com/harmless-tech/test-github-app")
}

async fn error404(uri: Uri) -> (StatusCode, String) {
    (StatusCode::NOT_FOUND, format!("Not found: {uri}"))
}
