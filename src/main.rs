mod fetch;
mod secure;
mod states;
mod webhooks;

use axum::{
    http::{StatusCode, Uri},
    response::Redirect,
    routing::get,
    Router,
};
use std::net::SocketAddr;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    println!("START!");

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "test_github_app=debug,tower_http=debug,axum::rejection=trace".into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let app = Router::new()
        .route("/", get(redirect_home))
        .route("/health/ready", get(health_ready))
        .nest("/webhooks", webhooks::get_routes().await)
        .fallback(error404)
        .with_state(states::AppState::new_empty())
        .layer(TraceLayer::new_for_http());

    // Allow Ctl-c exit
    tokio::spawn(async move {
        tracing::debug!("Listening for Ctl-c...");
        tokio::signal::ctrl_c().await.unwrap();
        std::process::exit(0);
    });

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn health_ready() -> String {
    "Ready!".to_string()
}

async fn redirect_home() -> Redirect {
    Redirect::temporary("https://github.com/harmless-tech/test-github-app")
}

async fn error404(uri: Uri) -> (StatusCode, String) {
    (StatusCode::NOT_FOUND, format!("Not found: {uri}"))
}
