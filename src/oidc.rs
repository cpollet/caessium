use crate::config::Config;
use anyhow::Context;
use oauth2::basic::*;
use oauth2::http::{HeaderMap, HeaderValue};
use oauth2::url::Url;
use oauth2::*;
use std::time::Duration;

pub struct OIDCClient {
    client: Client<
        BasicErrorResponse,
        BasicTokenResponse,
        BasicTokenIntrospectionResponse,
        StandardRevocableToken,
        BasicRevocationErrorResponse,
        EndpointSet,
        EndpointNotSet,
        EndpointNotSet,
        EndpointNotSet,
        EndpointSet,
    >,
    pkce: bool,
    http_client: reqwest::Client,
}

impl OIDCClient {
    pub fn new(config: &Config) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert("Accept", HeaderValue::from_static("application/json"));

        Self {
            client: BasicClient::new(ClientId::new(config.oidc.client_id.clone()))
                .set_client_secret(ClientSecret::new(config.oidc.client_secret.clone()))
                .set_auth_uri(AuthUrl::new(config.oidc.auth_url.clone()).unwrap())
                .set_token_uri(TokenUrl::new(config.oidc.token_url.clone()).unwrap())
                // Set the URL the user will be redirected to after the authorization process.
                .set_redirect_uri(RedirectUrl::new(config.oidc.redirect_uri.clone()).unwrap()),
            pkce: false,
            http_client: reqwest::ClientBuilder::new()
                // Following redirects opens the client up to SSRF vulnerabilities.
                .redirect(reqwest::redirect::Policy::none())
                .default_headers(headers)
                .build()
                .expect("HTTP Client should build"),
        }
    }

    pub fn authorize_url(&self) -> (Url, CsrfToken, Option<PkceCodeVerifier>) {
        let builder = self
            .client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("profile".to_string()));

        let (builder, pkce_verifier) = if self.pkce {
            // Generate a PKCE challenge.
            let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
            (
                builder.set_pkce_challenge(pkce_challenge),
                Some(pkce_verifier),
            )
        } else {
            (builder, None)
        };

        let (url, csrf_token) = builder.url();
        (url, csrf_token, pkce_verifier)
    }

    pub async fn exchange_code<C>(
        &self,
        authorization_code: C,
        pkce_verifier: Option<PkceCodeVerifier>,
    ) -> anyhow::Result<(String, Option<Duration>, Option<String>)>
    where
        C: Into<String>,
    {
        let req = self
            .client
            .exchange_code(AuthorizationCode::new(authorization_code.into()));

        let req = if let Some(pkce_verifier) = pkce_verifier {
            req.set_pkce_verifier(pkce_verifier)
        } else {
            req
        };

        let res = req
            .request_async(&self.http_client)
            .await
            .context("Could not exchange code")?;
        //dbg!(&res);

        Ok((
            res.access_token().secret().clone(),
            res.expires_in(),
            res.refresh_token().map(|t| t.secret().clone()),
        ))
    }

    pub async fn refresh<S>(
        &self,
        refresh_token: S,
    ) -> anyhow::Result<(String, Option<Duration>, Option<String>)>
    where
        S: Into<String>,
    {
        let refresh_token = RefreshToken::new(refresh_token.into());
        let req = self.client.exchange_refresh_token(&refresh_token);

        let res = req
            .request_async(&self.http_client)
            .await
            .context("Cound not refresh token")?;
        //dbg!(&res);

        Ok((
            res.access_token().secret().clone(),
            res.expires_in(),
            res.refresh_token().map(|t| t.secret().clone()),
        ))
    }
}
