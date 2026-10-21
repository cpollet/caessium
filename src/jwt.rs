use anyhow::Context;
use jsonwebtoken::{TokenData, Validation};
use jwks::Jwk;
use log::info;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::mem;
use std::ops::DerefMut;
use tokio::sync::RwLock;

pub struct Jwks {
    url: String,
    store: RwLock<jwks::Jwks>,
}

impl Jwks {
    pub async fn new<U>(url: U) -> anyhow::Result<Self>
    where
        U: Into<String>,
    {
        let url = url.into();
        Ok(Self {
            url: url.clone(),
            store: RwLock::new(Self::load_keys(url).await?),
        })
    }

    async fn load_keys<U>(url: U) -> anyhow::Result<jwks::Jwks>
    where
        U: Into<String>,
    {
        let url = url.into();
        info!("Load keys from {url}");
        jwks::Jwks::from_oidc_url(url)
            .await
            .context("Could not load JWKS")
    }

    pub async fn get_key<S>(&self, kid: S) -> anyhow::Result<Option<Jwk>>
    where
        S: AsRef<str>,
    {
        self.get_key_int(kid, true).await
    }

    async fn get_key_int<S>(&self, kid: S, refresh: bool) -> anyhow::Result<Option<Jwk>>
    where
        S: AsRef<str>,
    {
        let key = self.store.read().await.keys.get(kid.as_ref()).cloned();

        match key {
            Some(k) => Ok(Some(k)),
            None if refresh => {
                mem::swap(
                    &mut self.store.write().await.deref_mut().keys,
                    &mut Self::load_keys(&self.url).await?.keys,
                );
                Box::pin(self.get_key_int(kid, false)).await
            }
            None => Ok(None),
        }
    }
}

pub async fn validate<T>(jwks: &Jwks, access_token: &str) -> anyhow::Result<Option<TokenData<T>>>
where
    T: DeserializeOwned,
{
    let header =
        jsonwebtoken::decode_header(access_token).context("Error decoding access token header")?;
    let kid = header.kid.context("No kid found in header")?;

    let key = jwks
        .get_key(kid)
        .await
        .context("Could not fetch JWKs")?
        .context("Key not found")?;

    let mut validation = Validation::new(header.alg);
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.validate_aud = false;

    // validation.set_issuer(&["..."]);
    // validation.set_audience(&["..."]);

    Ok(jsonwebtoken::decode::<T>(&access_token, &key.decoding_key, &validation).ok())
}

#[derive(Deserialize)]
pub struct AccessToken {
    pub preferred_username: String,
}
