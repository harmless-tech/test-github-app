use once_cell::sync::Lazy;
use std::time::Duration;

pub static CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .user_agent(concat!(
            env!("CARGO_PKG_NAME"),
            "/",
            env!("CARGO_PKG_VERSION"),
        ))
        .timeout(Duration::new(60, 0))
        .connection_verbose(true)
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
        .https_only(true)
        .build()
        .expect("Could not build reqwest client!")
});
