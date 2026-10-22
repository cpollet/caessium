use crate::session::{SessionState, Ticket};
use std::collections::HashMap;

use anyhow::Context;
use redis::aio::MultiplexedConnection;
use redis::{AsyncTypedCommands, IntoConnectionInfo, SetExpiry, SetOptions};
use std::sync::Arc;
use tokio::sync::Mutex;

pub trait Store: Send + Sync {
    async fn set(
        &self,
        key: &Ticket,
        session_state: &SessionState,
        extend_ttl: bool,
    ) -> anyhow::Result<()>;

    async fn get(&self, key: &Ticket, extend_ttl: bool) -> anyhow::Result<Option<SessionState>>;
}

#[allow(unused)]
pub struct InMemoryStore {
    store: Arc<Mutex<HashMap<String, String>>>,
}

#[allow(unused)]
impl InMemoryStore {
    pub fn new() -> Self {
        Self {
            store: Default::default(),
        }
    }
}

impl Store for InMemoryStore {
    async fn set(
        &self,
        key: &Ticket,
        session_state: &SessionState,
        _extend_ttl: bool,
    ) -> anyhow::Result<()> {
        log::debug!("Storing {key:?} for {}", session_state.username);
        self.store
            .lock()
            .await
            .insert(key.id.clone(), key.encrypt(&session_state)?);
        Ok(())
    }

    async fn get(&self, key: &Ticket, _extend_ttl: bool) -> anyhow::Result<Option<SessionState>> {
        self.store
            .lock()
            .await
            .get(&key.id)
            .map(|s| key.decrypt(s))
            .transpose()
    }
}

pub struct RedisStore {
    conn: MultiplexedConnection,
}

impl RedisStore {
    pub async fn new<T>(params: T) -> anyhow::Result<Self>
    where
        T: IntoConnectionInfo,
    {
        Ok(Self {
            conn: redis::Client::open(params)
                .context("Could not create redis client")?
                .get_multiplexed_async_connection()
                .await
                .context("Could not connect to redis")?,
        })
    }
}

impl Store for RedisStore {
    async fn set(
        &self,
        key: &Ticket,
        session_state: &SessionState,
        extend_ttl: bool,
    ) -> anyhow::Result<()> {
        if let Some(exp) = session_state.expiration()
            && extend_ttl
        {
            log::debug!(
                "Store ession {key} for {username} with expiration at {exp} (max {exp_max})",
                key = key.id,
                username = session_state.username,
                exp_max = session_state.session_expires_at.unwrap_or(exp)
            );
            self.conn
                .clone()
                .set_options(
                    &key.id,
                    key.encrypt(&session_state)?,
                    SetOptions::default().with_expiration(SetExpiry::EXAT(exp.as_second() as u64)),
                )
                .await
                .context("Could not set key")
                .map(|_| ())
        } else {
            log::debug!(
                "Store ession {key} for {username} without expiration",
                key = key.id,
                username = session_state.username,
            );
            self.conn
                .clone()
                .set_options(
                    &key.id,
                    key.encrypt(&session_state)?,
                    SetOptions::default().with_expiration(SetExpiry::KEEPTTL),
                )
                .await
                .context("Could not set key")
                .map(|_| ())
        }
    }

    async fn get(&self, key: &Ticket, extend_ttl: bool) -> anyhow::Result<Option<SessionState>> {
        log::debug!("Fetch session {key} from redis", key = key.id);
        let session_state = self
            .conn
            .clone()
            .get(&key.id)
            .await
            .context("Could not get key")?
            .map(|s| key.decrypt::<_, SessionState>(&s))
            .transpose();

        if let Ok(Some(session_state)) = &session_state
            && extend_ttl
        {
            if let Some(exp) = session_state.expiration() {
                log::debug!(
                    "Session {key} now expires at {exp} (max {exp_max})",
                    key = key.id,
                    exp_max = session_state.session_expires_at.unwrap_or(exp)
                );
                self.conn
                    .clone()
                    .expire_at(&key.id, exp.as_second())
                    .await
                    .context("Could not set key expiration")?;
            }
        }

        session_state
    }
}

#[cfg(test)]
mod tests {
    use crate::session::{SessionState, Ticket};
    use crate::store::{InMemoryStore, Store};

    #[tokio::test]
    async fn test_in_memory_store_set_get() {
        let store = InMemoryStore::new();
        let ticket = Ticket::generate("cookie_name").unwrap();

        let session_state =
            SessionState::new("username", "at".into(), None, Some("rt".into()), None, None);
        store.set(&ticket, &session_state, false).await.unwrap();

        let loaded_session_state = store.get(&ticket, false).await.unwrap().unwrap();

        assert_eq!(loaded_session_state.access_token, "at".into());
        assert_eq!(loaded_session_state.refresh_token.unwrap(), "rt".into());
    }

    #[tokio::test]
    async fn test_in_memory_store_get_unknown_ticket() {
        let store = InMemoryStore::new();
        let ticket = Ticket::generate("cookie_name").unwrap();

        let loaded_session_state = store.get(&ticket, false).await.unwrap();
        assert!(loaded_session_state.is_none());
    }
}
