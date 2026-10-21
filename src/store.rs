use crate::session::{SessionState, Ticket};
use std::collections::HashMap;

use std::sync::Arc;
use tokio::sync::Mutex;

pub trait Store: Send + Sync {
    async fn set(&self, key: &Ticket, value: &SessionState) -> anyhow::Result<()>;

    async fn get(&self, key: &Ticket) -> anyhow::Result<Option<SessionState>>;
}

pub struct InMemoryStore {
    store: Arc<Mutex<HashMap<String, String>>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self {
            store: Default::default(),
        }
    }
}

impl Store for InMemoryStore {
    async fn set(&self, key: &Ticket, value: &SessionState) -> anyhow::Result<()> {
        log::info!("Storing {key:?} for {}", value.username);
        self.store
            .lock()
            .await
            .insert(key.ticket_id.clone(), key.encrypt(value)?);
        Ok(())
    }

    async fn get(&self, key: &Ticket) -> anyhow::Result<Option<SessionState>> {
        self.store
            .lock()
            .await
            .get(&key.ticket_id)
            .map(|s| key.decrypt(s))
            .transpose()
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

        let session_state = SessionState::new("username", "at", None, Some("rt"));
        store.set(&ticket, &session_state).await.unwrap();

        let loaded_session_state = store.get(&ticket).await.unwrap().unwrap();

        assert_eq!(
            loaded_session_state.access_token,
            session_state.access_token
        );
        assert_eq!(
            loaded_session_state.refresh_token,
            session_state.refresh_token
        );
    }

    #[tokio::test]
    async fn test_in_memory_store_get_unknown_ticket() {
        let store = InMemoryStore::new();
        let ticket = Ticket::generate("cookie_name").unwrap();

        let loaded_session_state = store.get(&ticket).await.unwrap();
        assert!(loaded_session_state.is_none());
    }
}
