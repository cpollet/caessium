mod config;
mod oidc;
mod session;
mod store;

use crate::config::Config;
use crate::oidc::OIDCClient;
use crate::session::{Cookie, SessionState, Ticket};
use crate::store::{InMemoryStore, Store};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Redirect};
use axum::routing::get;
use axum::{Json, Router};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::Cookie as HttpCookie;
use jiff::Timestamp;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;

// see http://localhost/realms/caessium/.well-known/openid-configuration
const CLIENT_ID: &str = "caessium";
const CLIENT_SECRET: &str = "IYa1ukFRJFVbofW5VsGl3b6QbHaEQXPz";
const AUTH_URL: &str = "http://localhost/realms/caessium/protocol/openid-connect/auth";
const TOKEN_URL: &str = "http://localhost/realms/caessium/protocol/openid-connect/token";

const SESSIUM_SESSIUM_BASE_URL: &str = "http://localhost:3000";
const SESSIUM_REDIRECT_URL: &str = "/sessions/start";
const SESSIUM_LOGIN_URL: &str = "/login";
const SESSIUM_TOKEN_URL: &str = "/sessions/get";

#[tokio::main]
async fn main() {
    let config = Config::new(
        CLIENT_ID,
        CLIENT_SECRET,
        AUTH_URL,
        TOKEN_URL,
        format!("{SESSIUM_SESSIUM_BASE_URL}{SESSIUM_REDIRECT_URL}"),
    );

    let listener = TcpListener::bind(format!("0.0.0.0:{}", config.http_port))
        .await
        .unwrap();

    let app = Router::new()
        .route(SESSIUM_LOGIN_URL, get(handle_login))
        .route(SESSIUM_REDIRECT_URL, get(handle_session_start))
        .route(SESSIUM_TOKEN_URL, get(handle_session_get))
        .with_state(Arc::new(AppState {
            oidc_client: OIDCClient::new(&config),
            store: InMemoryStore::new(),
            config,
        }));

    println!("Visit {SESSIUM_SESSIUM_BASE_URL}{SESSIUM_LOGIN_URL}");
    axum::serve(listener, app).await.unwrap();
}

async fn handle_login(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let (url, _csrf_token, _pkce_verifier) = state.oidc_client.authorize_url();
    Redirect::to(url.as_str())
}

async fn handle_session_start(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
    jar: CookieJar,
) -> Result<(CookieJar, impl IntoResponse), StatusCode> {
    if let Some(code) = params.get("code") {
        let (access_token, expires_in, refresh_token) =
            match state.oidc_client.exchange_code(code, None).await {
                Ok(res) => res,
                Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
            };

        let session_state = SessionState::new(access_token, expires_in, refresh_token);
        let ticket = Ticket::generate(&state.config.cookie_name).unwrap();
        state.store.set(&ticket, &session_state).await.unwrap();
        let cookie = ticket.into_cookie(&state.config.cookie_name);

        let mut http_cookie = HttpCookie::new(
            state.config.cookie_name.clone(),
            cookie.serialize(&state.config.cookie_sign_key),
        );
        http_cookie.set_path("/");
        http_cookie.set_secure(true);
        http_cookie.set_http_only(true);
        Ok((jar.add(http_cookie), Redirect::to(SESSIUM_TOKEN_URL)))
    } else {
        Err(StatusCode::BAD_REQUEST)
    }
}

async fn handle_session_get(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<impl IntoResponse, StatusCode> {
    let cookie = jar
        .get(state.config.cookie_name.as_str())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let cookie = Cookie::deserialize(
        cookie.value(),
        &state.config.cookie_name,
        &state.config.cookie_sign_key,
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let mut session = state
        .store
        .get(cookie.ticket())
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if session.is_expired()
        && let Some(refresh_token) = &session.refresh_token
    {
        let (access_token, expires_at, refresh_token) = state
            .oidc_client
            .refresh(refresh_token)
            .await
            .map_err(|_| StatusCode::UNAUTHORIZED)?;

        session.update_tokens(access_token, expires_at, refresh_token);

        state.store.set(cookie.ticket(), &session).await.map_err(|_| StatusCode::UNAUTHORIZED)?;
    }

    let mut headers = HeaderMap::new();
    if let Some(expires_at) = session.expires_at {
        let max_age = expires_at - Timestamp::now();
        let max_age = max_age.get_seconds() - 5;
        headers.insert(
            header::CACHE_CONTROL,
            format!("max-age: {max_age}",).parse().unwrap(),
        );
    }

    Ok((headers, Json(session.access_token)))
}

struct AppState {
    config: Config,
    oidc_client: OIDCClient,
    store: InMemoryStore, // todo: actual implementation should come from config
}
