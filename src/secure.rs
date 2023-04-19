use crate::{fetch, states::AppData};
use chrono::{DateTime, Duration, Utc};
use hmac::{digest::core_api::CoreWrapper, Hmac, HmacCore};
use jsonwebtoken::EncodingKey;
use once_cell::sync::Lazy;
use reqwest::{IntoUrl, RequestBuilder, Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use std::{
    env,
    future::Future,
    time::{SystemTime, UNIX_EPOCH},
};

type HmacSha256 = Hmac<Sha256>;

pub static WEBHOOK_MAC: Lazy<CoreWrapper<HmacCore<Sha256>>> = Lazy::new(|| {
    use hmac::digest::KeyInit;

    let secret = env::var("WEBHOOK_SECRET").unwrap();
    let secret = secret.trim().as_bytes();
    HmacSha256::new_from_slice(secret)
        .map_err(|_| ())
        .expect("Could not create HmacSha256 for private key")
});

pub static GH_APP_KEY: Lazy<EncodingKey> = Lazy::new(|| {
    let secret = env::var("GH_APP_KEY").unwrap();
    EncodingKey::from_rsa_pem(secret.as_bytes()).expect("Failed to get RSA private key!")
});

#[derive(Debug)]
pub struct AccessToken {
    token: String,
    expiry: DateTime<Utc>,
}
impl AccessToken {
    pub fn new() -> Self {
        Self {
            token: String::new(),
            expiry: DateTime::<Utc>::MIN_UTC,
        }
    }

    pub async fn get<U: IntoUrl>(&mut self, app_data: &AppData, url: U) -> impl Future<Output = Result<Response, reqwest::Error>> {
        let token = self.get_installation_token(app_data).await.expect("Could not get token");
        fetch::CLIENT.get(url).bearer_auth(token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28").send()
    }

    pub async fn post<U: IntoUrl>(&mut self, app_data: &AppData, url: U) -> impl Future<Output = Result<Response, reqwest::Error>> {
        let token = self.get_installation_token(app_data).await.expect("Could not get token");
        fetch::CLIENT.post(url).bearer_auth(token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28").send()
    }

    pub async fn post_json<U: IntoUrl>(&mut self, app_data: &AppData, url: U, payload: &Value) -> impl Future<Output = Result<Response, reqwest::Error>> {
        let token = self.get_installation_token(app_data).await.expect("Could not get token");
        fetch::CLIENT.post(url).bearer_auth(token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28").json(payload).send()
    }

    pub async fn patch_json<U: IntoUrl>(&mut self, app_data: &AppData, url: U, payload: &Value) -> impl Future<Output = Result<Response, reqwest::Error>> {
        let token = self.get_installation_token(app_data).await.expect("Could not get token");
        fetch::CLIENT.patch(url).bearer_auth(token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28").json(payload).send()
    }

    async fn get_installation_token(&mut self, app_data: &AppData) -> Result<String, ()> {
        if Utc::now() < self.expiry {
            return Ok(self.token.clone());
        }

        let app = {
            let lock = app_data.read().await;
            lock.clone()
                .expect("No APP_INFO for generating access tokens!")
        };

        let token = gen_jwt(app.0);
        let request = fetch::CLIENT
            .post(app.1)
            .bearer_auth(token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send();

        match request.await {
            Ok(data) => {
                let data: Value = data
                    .json()
                    .await
                    .expect("Did not receive json back from installation token request.");

                // Manufacture expiry
                let expiry = data.get("expires_at").unwrap().as_str().unwrap();
                let expiry = DateTime::parse_from_rfc3339(expiry).unwrap() - Duration::minutes(2);
                let expiry: DateTime<Utc> = expiry.into();
                tracing::debug!("New token will expire on: {expiry}");

                self.token = data.get("token").unwrap().as_str().unwrap().to_string();
                self.expiry = expiry;

                Ok(self.token.clone())
            }
            Err(err) => {
                tracing::error!("Installation token request failed.\n{err}");
                Err(())
            }
        }
    }
}
impl Default for AccessToken {
    fn default() -> Self {
        Self::new()
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
