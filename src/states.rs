use crate::secure::AccessToken;
use axum::extract::FromRef;
use bb8::Pool;
use bb8_redis::{redis::cmd, RedisConnectionManager};
use std::{env, sync::Arc};
use tokio::sync::RwLock;

pub type AppData = Arc<RwLock<Option<(u64, String)>>>;
pub type AppToken = Arc<RwLock<AccessToken>>;
pub type ConnectionPool = Option<Pool<RedisConnectionManager>>;

pub static IDENT_APP_ID: &str = "app_id";
pub static IDENT_TOKEN_URL: &str = "access_tokens_url";

#[derive(Debug, Clone)]
pub struct AppState {
    pub data: AppData,
    pub access_token: AppToken,
    pub pool: ConnectionPool,
}
impl AppState {
    pub fn new_empty() -> Self {
        Self {
            data: Arc::new(RwLock::new(None)),
            access_token: Arc::new(RwLock::new(AccessToken::new())),
            pool: None,
        }
    }

    async fn new(pool: Pool<RedisConnectionManager>) -> Self {
        let base = {
            let conn1 = pool.get();
            let conn2 = pool.get();

            let mut conn1 = conn1.await.unwrap();
            let id: Option<u64> = cmd("GET")
                .arg(IDENT_APP_ID)
                .query_async(&mut *conn1)
                .await
                .unwrap();
            tracing::debug!("APP_ID from persist: {id:?}");

            let mut conn2 = conn2.await.unwrap();
            let url: Option<String> = cmd("GET")
                .arg(IDENT_TOKEN_URL)
                .query_async(&mut *conn2)
                .await
                .unwrap();
            tracing::debug!("APP_TOKEN_URL from persist: {url:?}");

            match (id, url) {
                (Some(id), Some(url)) => Some((id, url)),
                (_, _) => None,
            }
        };

        Self {
            data: Arc::new(RwLock::new(base)),
            access_token: Arc::new(RwLock::new(AccessToken::new())),
            pool: Some(pool),
        }
    }
}
impl FromRef<AppState> for ConnectionPool {
    fn from_ref(input: &AppState) -> Self {
        input.pool.clone()
    }
}

pub async fn build_app_state() -> AppState {
    let manager = RedisConnectionManager::new(env::var("REDIS_URL").unwrap()).unwrap();
    let pool = bb8::Pool::builder().build(manager).await.unwrap();

    AppState::new(pool).await
}
