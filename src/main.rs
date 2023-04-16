use axum::{
    http::{StatusCode, Uri},
    routing::get,
    Router,
};
use bb8_redis::RedisConnectionManager;
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    println!("Hello, world!");

    let manager = RedisConnectionManager::new(std::env::var("REDIS_URL").unwrap()).unwrap();
    let pool = bb8::Pool::builder().build(manager).await.unwrap();

    let app = Router::new()
        .route("/health/ready", get(|| async { "Ready!".to_string() }))
        .fallback(error404)
        .with_state(pool);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn error404(uri: Uri) -> (StatusCode, String) {
    (StatusCode::NOT_FOUND, format!("Not found: {uri}"))
}
