use crate::secrets::{Secret, SecretString};
use aes_gcm::aead::array::Array;
use aes_gcm::aead::consts::U16;
use aes_gcm::{
    Aes128Gcm, Nonce,
    aead::{Aead, Generate, Key, KeyInit},
};
use anyhow::{Context, anyhow, bail};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use getrandom::Error;
use jiff::Timestamp;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::digest::Output;
use sha2::{Digest, Sha256};
use std::fmt::{Debug, Display};
use std::time::Duration;
use zeroize::Zeroize;

#[derive(Debug)]
pub struct Ticket {
    pub id: String,
    secret: Secret<Array<u8, U16>>,
}

impl Ticket {
    pub fn generate(cookie_name: &str) -> Result<Ticket, Error> {
        let mut buf = [0u8; 16];
        getrandom::fill(&mut buf)?;

        Ok(Self {
            id: format!("{cookie_name}-{id}", id = hex::encode(buf)),
            secret: Key::<Aes128Gcm>::generate().into(),
        })
    }

    /// Ticket is serialized as `{version} + '.' + {ticketId as base64} + '.' + {secret as base64}`
    pub fn serialize(&self) -> SecretString {
        format!(
            "0.{ticket_id}.{secret}",
            ticket_id = BASE64_URL_SAFE_NO_PAD.encode(self.id.as_bytes()),
            secret = BASE64_URL_SAFE_NO_PAD.encode(self.secret.as_secret_ref())
        )
        .into()
    }

    //todo: the `ticket` param should be `Secret`
    pub fn deserialize(ticket: &str) -> anyhow::Result<Ticket> {
        let mut parts = ticket.split(".");

        let version = parts.next().context("Missing version")?;

        match version {
            "0" => {
                let ticket_id = BASE64_URL_SAFE_NO_PAD
                    .decode(parts.next().context("Missing ticket ID")?)
                    .context("Invalid ticket ID format")?;

                if ticket_id.is_empty() {
                    bail!("Ticket ID cannot be empty");
                }

                let mut secret = Secret::from(Array::from([0u8; 16]));
                BASE64_URL_SAFE_NO_PAD
                    .decode_slice(
                        parts.next().context("Missing secret")?,
                        secret.as_secret_mut(),
                    )
                    .context("Invalid secret")?;

                if parts.next().is_some() {
                    bail!("Invalid format");
                }

                Ok(Ticket {
                    id: String::from_utf8(ticket_id).context("Invalid ticket ID")?,
                    secret,
                })
            }
            _ => Err(anyhow!("Unsupported ticket version")),
        }
    }

    pub fn into_cookie(self, cookie_name: &str) -> Cookie {
        Cookie::new(cookie_name, self)
    }

    pub fn encrypt<T>(&self, session_state: &T) -> anyhow::Result<String>
    where
        T: Serialize,
    {
        let session_state =
            serde_json::to_string(session_state).context("Failed to serialize session state")?;

        let nonce = Nonce::generate();

        let mut ciphertext = self
            .cipher()
            .encrypt(&nonce, session_state.as_ref())
            .context("Encryption failed")?;

        ciphertext.extend_from_slice(nonce.as_slice());

        Ok(BASE64_URL_SAFE_NO_PAD.encode(ciphertext))
    }

    fn cipher(&self) -> Aes128Gcm {
        Aes128Gcm::new(self.secret.as_secret_ref())
    }

    // todo: the `payload` should be `Secret`
    pub fn decrypt<S, T>(&self, payload: S) -> anyhow::Result<T>
    where
        S: AsRef<str>,
        T: DeserializeOwned,
    {
        let payload = BASE64_URL_SAFE_NO_PAD
            .decode(payload.as_ref().as_bytes())
            .context("Invalid encoding")?;

        const NONCE_SIZE: usize = 12;
        if payload.len() < NONCE_SIZE {
            bail!("Invalid payload size");
        };

        let nonce = Nonce::slice_as_array(&payload[payload.len() - NONCE_SIZE..])
            .expect("We have at elast nonce len bytes");

        let ciphertext = &payload[..payload.len() - NONCE_SIZE];

        let cleartext = self
            .cipher()
            .decrypt(nonce, ciphertext)
            .context("Could not decrypt")?;

        serde_json::from_slice::<T>(cleartext.as_slice())
            .context("Failed to deserialize session state")
    }
}

impl Display for Ticket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TicketId={}", self.id)
    }
}

#[derive(Debug)]
pub struct Cookie {
    ticket: Ticket,
    name: String,
    /// generation timestamp
    timestamp: i64,
}

impl Cookie {
    fn new(cookie_name: &str, ticket: Ticket) -> Cookie {
        Self {
            ticket,
            name: cookie_name.to_string(),
            timestamp: Timestamp::now().as_second(),
        }
    }

    pub fn serialize<S>(&self, cookie_signing_key: &Secret<S>) -> SecretString
    where
        S: AsRef<[u8]> + Zeroize,
    {
        let ticket = self.ticket.serialize();
        let timestamp = self.timestamp.to_string();

        let signature = BASE64_URL_SAFE_NO_PAD.encode(
            Cookie::sign(
                cookie_signing_key,
                &[&"0", &self.name, ticket.as_secret_ref(), &timestamp],
            )
            .as_slice(),
        );

        format!("0|{}|{}|{}", ticket.as_secret_ref(), timestamp, signature).into()
    }

    fn sign<K>(key: &Secret<K>, vals: &[&dyn AsRef<[u8]>]) -> Output<Sha256>
    where
        K: AsRef<[u8]> + Zeroize,
    {
        let mut hasher = Sha256::new();

        hasher.update(key.as_secret_ref());

        for val in vals {
            hasher.update(val.as_ref());
        }

        hasher.finalize()
    }

    pub fn deserialize<C, S>(
        cookie: C,
        cookie_name: &str,
        cookie_signing_key: &Secret<S>,
    ) -> anyhow::Result<Cookie>
    where
        C: AsRef<str>,
        S: AsRef<[u8]> + Zeroize,
    {
        let mut parts = cookie.as_ref().split("|");
        let version = parts.next().context("Missing version")?;
        match version {
            "0" => {
                let ticket = parts.next().context("Missing ticket")?;
                let timestamp = parts.next().context("Missing timestamp")?;
                let actual_signature = parts.next().context("Missing signature")?;
                if parts.next().is_some() {
                    bail!("Invalid format");
                }

                let expected_signature = BASE64_URL_SAFE_NO_PAD.encode(
                    Cookie::sign(
                        cookie_signing_key,
                        &[&version, &cookie_name, &ticket, &timestamp],
                    )
                    .as_slice(),
                );

                if actual_signature != expected_signature {
                    bail!("Invalid signature");
                }

                Ok(Self {
                    ticket: Ticket::deserialize(ticket)?,
                    name: cookie_name.to_string(),
                    timestamp: timestamp.parse::<i64>().context("Invalid timestamp")?,
                })
            }
            _ => bail!("Unsupported version"),
        }
    }

    pub fn ticket(&self) -> &Ticket {
        &self.ticket
    }
}

// type SessionState struct {
//     CreatedAt *time.Time `msgpack:"ca,omitempty"`
//     ExpiresOn *time.Time `msgpack:"eo,omitempty"`
//
//     AccessToken  string `msgpack:"at,omitempty"`
//     IDToken      string `msgpack:"it,omitempty"`
//     RefreshToken string `msgpack:"rt,omitempty"`
//
//     Nonce []byte `msgpack:"n,omitempty"`
//
//     Email             string   `msgpack:"e,omitempty"`
//     User              string   `msgpack:"u,omitempty"`
//     Groups            []string `msgpack:"g,omitempty"`
//     PreferredUsername string   `msgpack:"pu,omitempty"`
//
//     // Additional claims
//     AdditionalClaims map[string]interface{} `msgpack:"ac,omitempty"`
//
// // Internal helpers, not serialized
// Clock     func() time.Time `msgpack:"-"` // override for time.Now, for testing
// Lock      Lock             `msgpack:"-"`
// Refreshed bool             `msgpack:"-"` // indicates whether the session was refreshed
// }

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionState {
    #[serde(rename = "sub")]
    pub username: String,
    #[serde(rename = "at")]
    pub access_token: SecretString,
    #[serde(rename = "exp")]
    pub access_token_expires_at: Option<Timestamp>,
    #[serde(rename = "rt")]
    pub refresh_token: Option<SecretString>,
    /// hard session timeout
    pub session_expires_at: Option<Timestamp>,
    pub session_idle_timeout: Option<Duration>,
}

impl SessionState {
    // todo builder/wither
    pub fn new<U, AT, RT>(
        username: U,
        access_token: Secret<AT>,
        expires_in: Option<Duration>,
        refresh_token: Option<Secret<RT>>,
        session_expires_in: Option<Duration>,
        session_idle_timeout: Option<Duration>,
    ) -> Self
    where
        U: Into<String>,
        AT: Into<String> + Default + Zeroize,
        RT: Into<String> + Default + Zeroize,
    {
        Self {
            username: username.into(),
            access_token: access_token.inner_into(),
            access_token_expires_at: expires_in.map(|d| Timestamp::now().checked_add(d).unwrap()),
            refresh_token: refresh_token.map(|s| s.inner_into()),
            session_expires_at: session_expires_in
                .map(|d| Timestamp::now().checked_add(d).unwrap()),
            session_idle_timeout,
        }
    }

    pub fn is_access_token_expired(&self) -> bool {
        match self.access_token_expires_at {
            None => false,
            Some(expires_at) => expires_at <= Timestamp::now(),
        }
    }

    pub fn update_tokens<AT, RT>(
        &mut self,
        access_token: Secret<AT>,
        access_token_expires_in: Option<Duration>,
        refresh_token: Option<Secret<RT>>,
    ) where
        AT: Into<String> + Default + Zeroize,
        RT: Into<String> + Default + Zeroize,
    {
        let access_token = access_token.inner_into();
        if self.access_token != access_token {
            log::trace!("access_token updated");
        }
        self.access_token = access_token;

        self.access_token_expires_at =
            access_token_expires_in.map(|d| Timestamp::now().checked_add(d).unwrap());

        let refresh_token = refresh_token.map(|r| r.inner_into());
        if self.refresh_token != refresh_token {
            log::trace!("refresh_token updated");
        }
        self.refresh_token = refresh_token.map(|s| s.inner_into());
    }

    pub fn expiration(&self) -> Option<Timestamp> {
        let idle_exp = self
            .session_idle_timeout
            .map(|d| Timestamp::now().checked_add(d).unwrap())
            .or(self.session_expires_at);

        match (idle_exp, self.session_expires_at) {
            (Some(idle_exp), Some(hard_exp)) => Some(idle_exp.min(hard_exp)),
            (Some(idle_exp), None) => Some(idle_exp),
            (None, Some(hard_exp)) => Some(hard_exp),
            (None, None) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::secrets::Secret;
    use crate::session::{Cookie, SessionState, Ticket};
    use base64::Engine;
    use base64::prelude::BASE64_URL_SAFE_NO_PAD;
    use std::cell::LazyCell;
    use std::time::Duration;

    const SINGING_KEY: LazyCell<Secret<String>> =
        LazyCell::new(|| Secret::from("secret_key".to_string()));

    #[test]
    fn test_ticket_debug() {
        let ticket = Ticket::generate("cookie_name").expect("Can generate ticket");
        let debug = format!("{:?}", ticket);
        assert!(debug.contains(&ticket.id), "ticket id not present");
        assert!(debug.contains("secret: [redacted]"), "secret not present");
    }

    #[test]
    fn test_ticket_display() {
        let ticket = Ticket::generate("cookie_name").expect("Can generate ticket");
        let display = format!("{}", ticket);
        assert!(display.contains(&ticket.id), "ticket id not present");
        assert!(!display.contains("[redacted]"), "secret not present");
    }

    #[test]
    fn test_ticket_serialize_deserialize() {
        let ticket = Ticket::generate("cookie_name").expect("Can generate ticket");
        let serialized_ticket = ticket.serialize();
        let deserialized_ticket =
            Ticket::deserialize(serialized_ticket.as_secret_ref()).expect("Can deserialize ticket");

        assert_eq!(deserialized_ticket.id, ticket.id,);
        assert_eq!(deserialized_ticket.secret, ticket.secret,);
    }

    #[test]
    fn test_ticket_deserialize_invalid_version() {
        let ticket = "1.";
        let deserialization_err = Ticket::deserialize(&ticket).expect_err("Can deserialize ticket");

        assert_eq!(
            deserialization_err.to_string(),
            "Unsupported ticket version"
        );
    }

    #[test]
    fn test_ticket_deserialize_missing_ticket_id() {
        let ticket = "0";
        let deserialization_err = Ticket::deserialize(&ticket).expect_err("Can deserialize ticket");

        assert_eq!(deserialization_err.to_string(), "Missing ticket ID");
    }

    #[test]
    fn test_ticket_deserialize_empty_ticket_id() {
        let ticket = "0.";
        let deserialization_err = Ticket::deserialize(&ticket).expect_err("Can deserialize ticket");

        assert_eq!(deserialization_err.to_string(), "Ticket ID cannot be empty");
    }

    #[test]
    fn test_ticket_deserialize_invalid_ticket_id() {
        let ticket = "0.invalid";
        let deserialization_err = Ticket::deserialize(&ticket).expect_err("Can deserialize ticket");

        assert_eq!(deserialization_err.to_string(), "Invalid ticket ID format");
    }

    #[test]
    fn test_ticket_deserialize_missing_secret() {
        let ticket = "0.b2s";
        let deserialization_err = Ticket::deserialize(&ticket).expect_err("Can deserialize ticket");

        assert_eq!(deserialization_err.to_string(), "Missing secret");
    }

    #[test]
    fn test_ticket_deserialize_invalid_secret() {
        let ticket = "0.b2s.invalid";
        let deserialization_err = Ticket::deserialize(&ticket).expect_err("Can deserialize ticket");

        assert_eq!(deserialization_err.to_string(), "Invalid secret");
    }

    #[test]
    fn test_ticket_deserialize_invalid_format() {
        let ticket = "0.b2s.b2s.invalid";
        let deserialization_err = Ticket::deserialize(&ticket).expect_err("Can deserialize ticket");

        assert_eq!(deserialization_err.to_string(), "Invalid format");
    }

    #[test]
    fn test_ticket_encrypt_decrypt() {
        let ticket = Ticket::generate("cookie_name").expect("Can generate ticket");
        let session_state =
            SessionState::new("username", "at".into(), None, Some("rt".into()), None, None);
        let encrypted_session_state = ticket
            .encrypt(&session_state)
            .expect("Can encrypt session state");
        let decrypted_session_state = ticket
            .decrypt::<_, SessionState>(encrypted_session_state)
            .expect("Can decrypt session state");

        assert_eq!(
            decrypted_session_state.access_token,
            session_state.access_token,
        );
        assert_eq!(
            decrypted_session_state.refresh_token,
            session_state.refresh_token,
        );
    }

    #[test]
    fn test_ticket_decrypt_invalid_encoding() {
        let ticket = Ticket::generate("cookie_name").expect("Can generate ticket");
        let decrypted_session_state_err = ticket
            .decrypt::<_, SessionState>("invalid")
            .expect_err("Can decrypt session state");

        assert_eq!(decrypted_session_state_err.to_string(), "Invalid encoding");
    }

    #[test]
    fn test_ticket_decrypt_invalid_payload_size() {
        let ticket = Ticket::generate("cookie_name").expect("Can generate ticket");
        let decrypted_session_state_err = ticket
            .decrypt::<_, SessionState>(BASE64_URL_SAFE_NO_PAD.encode("invalid"))
            .expect_err("Can decrypt session state");

        assert_eq!(
            decrypted_session_state_err.to_string(),
            "Invalid payload size"
        );
    }

    #[test]
    fn test_ticket_decrypt_invalid_payload() {
        let ticket = Ticket::generate("cookie_name").expect("Can generate ticket");
        let decrypted_session_state_err = ticket
            .decrypt::<_, SessionState>("RVptNnl0aHlLQk52NnN5Y0x0d3BhVFkzcHo4cXgz")
            .expect_err("Can decrypt session state");

        assert_eq!(decrypted_session_state_err.to_string(), "Could not decrypt");
    }

    #[test]
    fn test_cookie_serialize_deserialize() {
        let cookie = Ticket::generate("cookie_name")
            .expect("Can generate ticket")
            .into_cookie("cookie_name");
        let serialized_cookie = cookie.serialize(&SINGING_KEY);
        let deserialized_cookie = Cookie::deserialize(
            serialized_cookie.as_secret_ref(),
            "cookie_name",
            &SINGING_KEY,
        )
        .expect("Can deserialize cookie");

        assert_eq!(deserialized_cookie.name, cookie.name);
        assert_eq!(deserialized_cookie.timestamp, cookie.timestamp);
        assert_eq!(deserialized_cookie.ticket.id, cookie.ticket.id);
        assert_eq!(deserialized_cookie.ticket.secret, cookie.ticket.secret);
    }

    #[test]
    fn test_cookie_deserialize_invalid_version() {
        let deserialized_cookie_err = Cookie::deserialize("1.", "cookie_name", &SINGING_KEY)
            .expect_err("Can deserialize cookie");

        assert_eq!(deserialized_cookie_err.to_string(), "Unsupported version");
    }

    #[test]
    fn test_cookie_deserialize_missing_ticket() {
        let deserialized_cookie_err = Cookie::deserialize("0", "cookie_name", &SINGING_KEY)
            .expect_err("Can deserialize cookie");

        assert_eq!(deserialized_cookie_err.to_string(), "Missing ticket");
    }

    #[test]
    fn test_cookie_deserialize_missing_timestamp() {
        let deserialized_cookie_err = Cookie::deserialize("0|ticket", "cookie_name", &SINGING_KEY)
            .expect_err("Can deserialize cookie");

        assert_eq!(deserialized_cookie_err.to_string(), "Missing timestamp");
    }

    #[test]
    fn test_cookie_deserialize_missing_signature() {
        let deserialized_cookie_err =
            Cookie::deserialize("0|ticket|timestamp", "cookie_name", &SINGING_KEY)
                .expect_err("Can deserialize cookie");

        assert_eq!(deserialized_cookie_err.to_string(), "Missing signature");
    }

    #[test]
    fn test_cookie_deserialize_invalid_format() {
        let deserialized_cookie_err =
            Cookie::deserialize("0|ticket|timestamp|signature|", "cookie_name", &SINGING_KEY)
                .expect_err("Can deserialize cookie");

        assert_eq!(deserialized_cookie_err.to_string(), "Invalid format");
    }

    #[test]
    fn test_cookie_deserialize_invalid_signature() {
        let deserialized_cookie_err =
            Cookie::deserialize("0|ticket|timestamp|signature", "cookie_name", &SINGING_KEY)
                .expect_err("Can deserialize cookie");

        assert_eq!(deserialized_cookie_err.to_string(), "Invalid signature");
    }
}
