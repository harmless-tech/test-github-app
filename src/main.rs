use axum::{
    http::{StatusCode, Uri},
    routing::get,
    Router,
};
use bb8_redis::RedisConnectionManager;
use std::net::SocketAddr;
use axum::response::Redirect;

#[tokio::main]
async fn main() {
    println!("Hello, world!");

    let manager = RedisConnectionManager::new(std::env::var("REDIS_URL").unwrap()).unwrap();
    let pool = bb8::Pool::builder().build(manager).await.unwrap();

    let app = Router::new()
        .route("/health/ready", get(|| async { "Ready!".to_string() }))
        .route("/", get(redirect))
        .fallback(error404)
        .with_state(pool);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn webhook() -> StatusCode {
    StatusCode::FORBIDDEN
}

async fn redirect() -> Redirect {
    Redirect::temporary("https://github.com/harmless-tech/test-github-app")
}

async fn error404(uri: Uri) -> (StatusCode, String) {
    (StatusCode::NOT_FOUND, format!("Not found: {uri}"))
}
