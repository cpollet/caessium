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
use serde::{Deserialize, Serialize};
use sha2::digest::Output;
use sha2::{Digest, Sha256};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Ticket {
    pub ticket_id: String,
    secret: Array<u8, U16>,
}

impl Ticket {
    pub fn generate(cookie_name: &str) -> Result<Ticket, Error> {
        let mut buf = [0u8; 16];
        getrandom::fill(&mut buf)?;

        Ok(Self {
            ticket_id: format!("{cookie_name}-{id}", id = hex::encode(buf)),
            secret: Key::<Aes128Gcm>::generate(),
        })
    }

    /// Ticket is serialized as `{version} + '.' + {ticketId as base64} + '.' + {secret as base64}`
    pub fn serialize(&self) -> String {
        format!(
            "0.{ticket_id}.{secret}",
            ticket_id = BASE64_URL_SAFE_NO_PAD.encode(self.ticket_id.as_bytes()),
            secret = BASE64_URL_SAFE_NO_PAD.encode(self.secret.0.as_slice())
        )
    }

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

                let mut secret = [0u8; 16];
                BASE64_URL_SAFE_NO_PAD
                    .decode_slice(parts.next().context("Missing secret")?, &mut secret)
                    .context("Invalid secret")?;

                if parts.next().is_some() {
                    bail!("Invalid format");
                }

                Ok(Ticket {
                    ticket_id: String::from_utf8(ticket_id).context("Invalid ticket ID")?,
                    secret: From::from(secret),
                })
            }
            _ => Err(anyhow!("Unsupported ticket version")),
        }
    }

    pub fn into_cookie(self, cookie_name: &str) -> Cookie {
        Cookie::new(cookie_name, self)
    }

    pub fn encrypt(&self, session_state: &SessionState) -> anyhow::Result<String> {
        let session_state =
            serde_json::to_string(session_state).context("Failed to serialize session state")?;
        Ok(BASE64_URL_SAFE_NO_PAD.encode(self.encrypt_int(session_state)?))
    }

    fn encrypt_int<P>(&self, payload: P) -> anyhow::Result<Vec<u8>>
    where
        P: AsRef<[u8]>,
    {
        let nonce = Nonce::generate();

        let mut ciphertext = self
            .cipher()
            .encrypt(&nonce, payload.as_ref())
            .context("Encryption failed")?;

        ciphertext.extend_from_slice(nonce.as_slice());

        Ok(ciphertext)
    }

    fn cipher(&self) -> Aes128Gcm {
        Aes128Gcm::new(&self.secret)
    }

    pub fn decrypt<S>(&self, payload: S) -> anyhow::Result<SessionState>
    where
        S: AsRef<str>,
    {
        serde_json::from_slice::<SessionState>(
            self.decrypt_int(
                BASE64_URL_SAFE_NO_PAD
                    .decode(payload.as_ref().as_bytes())
                    .context("Invalid encoding")?,
            )?
            .as_slice(),
        )
        .context("Failed to deserialize session state")
    }

    fn decrypt_int<P>(&self, payload: P) -> anyhow::Result<Vec<u8>>
    where
        P: AsRef<[u8]>,
    {
        let payload = payload.as_ref();

        const NONCE_SIZE: usize = 12;
        if payload.len() < NONCE_SIZE {
            bail!("Invalid payload size");
        };

        let nonce = Nonce::slice_as_array(&payload[payload.len() - NONCE_SIZE..])
            .expect("We have at elast nonce len bytes");

        let ciphertext = &payload[..payload.len() - NONCE_SIZE];

        self.cipher()
            .decrypt(nonce, ciphertext)
            .context("Could not decrypt")
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

    pub fn serialize<S>(&self, secret: S) -> String
    where
        S: AsRef<[u8]>,
    {
        let ticket = self.ticket.serialize();
        let timestamp = self.timestamp.to_string();

        let signature = BASE64_URL_SAFE_NO_PAD
            .encode(Cookie::sign(secret, &[&"0", &self.name, &ticket, &timestamp]).as_slice());

        format!("0|{}|{}|{}", ticket, timestamp, signature)
    }

    fn sign<K>(key: K, vals: &[&dyn AsRef<[u8]>]) -> Output<Sha256>
    where
        K: AsRef<[u8]>,
    {
        let mut hasher = Sha256::new();

        hasher.update(key.as_ref());

        for val in vals {
            hasher.update(val.as_ref());
        }

        hasher.finalize()
    }

    pub fn deserialize<C, S>(cookie: C, cookie_name: &str, secret: S) -> anyhow::Result<Cookie>
    where
        C: AsRef<str>,
        S: AsRef<[u8]>,
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
                    Cookie::sign(secret, &[&version, &cookie_name, &ticket, &timestamp]).as_slice(),
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
    #[serde(rename = "at")]
    pub access_token: String,
    #[serde(rename = "exp")]
    pub expires_at: Option<Timestamp>,
    #[serde(rename = "rt")]
    pub refresh_token: Option<String>,
}

impl SessionState {
    pub fn new<AT, RT>(
        access_token: AT,
        expires_in: Option<Duration>,
        refresh_token: Option<RT>,
    ) -> Self
    where
        AT: Into<String>,
        RT: Into<String>,
    {
        Self {
            access_token: access_token.into(),
            expires_at: expires_in.map(|d| Timestamp::now().checked_add(d).unwrap()),
            refresh_token: refresh_token.map(|s| s.into()),
        }
    }

    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            None => false,
            Some(expires_at) => expires_at <= Timestamp::now(),
        }
    }

    pub fn update_tokens<AT, RT>(
        &mut self,
        access_token: AT,
        expires_in: Option<Duration>,
        refresh_token: Option<RT>,
    ) where
        AT: Into<String>,
        RT: Into<String>,
    {
        self.access_token = access_token.into();
        self.expires_at = expires_in.map(|d| Timestamp::now().checked_add(d).unwrap());
        self.refresh_token = refresh_token.map(|s| s.into());
    }
}

#[cfg(test)]
mod tests {
    use crate::session::{Cookie, SessionState, Ticket};
    use base64::Engine;
    use base64::prelude::BASE64_URL_SAFE_NO_PAD;
    use std::time::Duration;

    #[test]
    fn test_ticket_serialize_deserialize() {
        let ticket = Ticket::generate("cookie_name").expect("Can generate ticket");
        let serialized_ticket = ticket.serialize();
        let deserialized_ticket =
            Ticket::deserialize(&serialized_ticket).expect("Can deserialize ticket");

        assert_eq!(deserialized_ticket.ticket_id, ticket.ticket_id,);
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
        let session_state = SessionState::new("at", None, Some("rt"));
        let encrypted_session_state = ticket
            .encrypt(&session_state)
            .expect("Can encrypt session state");
        let decrypted_session_state = ticket
            .decrypt(encrypted_session_state)
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
            .decrypt("invalid")
            .expect_err("Can decrypt session state");

        assert_eq!(decrypted_session_state_err.to_string(), "Invalid encoding");
    }

    #[test]
    fn test_ticket_decrypt_invalid_payload_size() {
        let ticket = Ticket::generate("cookie_name").expect("Can generate ticket");
        let decrypted_session_state_err = ticket
            .decrypt(BASE64_URL_SAFE_NO_PAD.encode("invalid"))
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
            .decrypt("RVptNnl0aHlLQk52NnN5Y0x0d3BhVFkzcHo4cXgz")
            .expect_err("Can decrypt session state");

        assert_eq!(decrypted_session_state_err.to_string(), "Could not decrypt");
    }

    #[test]
    fn test_cookie_serialize_deserialize() {
        let cookie = Ticket::generate("cookie_name")
            .expect("Can generate ticket")
            .into_cookie("cookie_name");
        let serialized_cookie = cookie.serialize("secret_key");
        let deserialized_cookie =
            Cookie::deserialize(serialized_cookie, "cookie_name", "secret_key")
                .expect("Can deserialize cookie");

        assert_eq!(deserialized_cookie.name, cookie.name);
        assert_eq!(deserialized_cookie.timestamp, cookie.timestamp);
        assert_eq!(
            deserialized_cookie.ticket.ticket_id,
            cookie.ticket.ticket_id
        );
        assert_eq!(deserialized_cookie.ticket.secret, cookie.ticket.secret);
    }

    #[test]
    fn test_cookie_deserialize_invalid_version() {
        let deserialized_cookie_err = Cookie::deserialize("1.", "cookie_name", "secret_key")
            .expect_err("Can deserialize cookie");

        assert_eq!(deserialized_cookie_err.to_string(), "Unsupported version");
    }

    #[test]
    fn test_cookie_deserialize_missing_ticket() {
        let deserialized_cookie_err = Cookie::deserialize("0", "cookie_name", "secret_key")
            .expect_err("Can deserialize cookie");

        assert_eq!(deserialized_cookie_err.to_string(), "Missing ticket");
    }

    #[test]
    fn test_cookie_deserialize_missing_timestamp() {
        let deserialized_cookie_err = Cookie::deserialize("0|ticket", "cookie_name", "secret_key")
            .expect_err("Can deserialize cookie");

        assert_eq!(deserialized_cookie_err.to_string(), "Missing timestamp");
    }

    #[test]
    fn test_cookie_deserialize_missing_signature() {
        let deserialized_cookie_err =
            Cookie::deserialize("0|ticket|timestamp", "cookie_name", "secret_key")
                .expect_err("Can deserialize cookie");

        assert_eq!(deserialized_cookie_err.to_string(), "Missing signature");
    }

    #[test]
    fn test_cookie_deserialize_invalid_format() {
        let deserialized_cookie_err =
            Cookie::deserialize("0|ticket|timestamp|signature|", "cookie_name", "secret_key")
                .expect_err("Can deserialize cookie");

        assert_eq!(deserialized_cookie_err.to_string(), "Invalid format");
    }

    #[test]
    fn test_cookie_deserialize_invalid_signature() {
        let deserialized_cookie_err =
            Cookie::deserialize("0|ticket|timestamp|signature", "cookie_name", "secret_key")
                .expect_err("Can deserialize cookie");

        assert_eq!(deserialized_cookie_err.to_string(), "Invalid signature");
    }
}
