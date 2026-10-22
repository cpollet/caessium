use crate::secrets::{Secret, SecretString};

pub struct Config {
    pub cookie_name: String,
    pub cookie_sign_key: Secret<Vec<u8>>,
    pub oidc: OICDConfig,
    pub http_port: u16,
}

pub struct OICDConfig {
    pub client_id: String,
    pub client_secret: SecretString,
    pub auth_url: String,
    pub token_url: String,
    pub redirect_uri: String,
}

impl Config {
    pub fn new<ID, Secret, AuthUrl, TokenUrl, RedirectUri>(
        client_id: ID,
        client_secret: Secret,
        auth_url: AuthUrl,
        token_url: TokenUrl,
        redirect_url: RedirectUri,
    ) -> Self
    where
        ID: Into<String>,
        Secret: Into<SecretString>,
        AuthUrl: Into<String>,
        TokenUrl: Into<String>,
        RedirectUri: Into<String>,
    {
        Self {
            cookie_name: "caessium_sid".to_string(),
            cookie_sign_key: "secret".as_bytes().to_vec().into(),
            oidc: OICDConfig {
                client_id: client_id.into(),
                client_secret: client_secret.into(),
                auth_url: auth_url.into(),
                token_url: token_url.into(),
                redirect_uri: redirect_url.into(),
            },
            http_port: 3000,
        }
    }
}
