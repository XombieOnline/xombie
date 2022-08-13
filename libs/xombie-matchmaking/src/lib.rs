use log::error;

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::Mutex;

use xblive::addr::Addr;
use xblive::crypto::primitives::KeyId;
use xblive::service::matchmaking::SearchAttribute;
use xblive::ver::LibraryVersion;

use xbox_sys::account::Xuid;
use xbox_sys::crypto::SymmetricKey;

pub struct CreatedSession {
    pub session_id: KeyId,
    pub key_exchange_key: SymmetricKey,
}

#[derive(Debug)]
pub enum SessionCreateError {
    UnableToGenerateSessionId,
    OverlappingCreationTime,
}

#[derive(Debug)]
pub enum SessionDeleteError {
}

#[derive(Debug)]
pub enum SessionUpdateError {
    SessionIdNotFound,
    UserMismatch,
    TitleMismatch,
    HostAddressMismatch,
}

#[derive(Debug)]
pub enum SessionSearchError {
}

pub struct Matchmaking {
    internal_state: Arc<Mutex<InternalState>>,
}

impl Debug for Matchmaking {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Matchmaking{{}}")
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Users {
    pub machine: Xuid,
    pub user: Vec<Xuid>,
}

impl Matchmaking {
    pub fn new() -> Self {
        Matchmaking {
            internal_state: Arc::new(Mutex::new(InternalState::new())),
        }
    }

    pub async fn create_session(
        &self,
        users: Users,
        title: Title,
        host_address: Addr,
        public_open: u32,
        private_open: u32,
        public_filled: u32,
        private_filled: u32,
        attributes: Vec<SearchAttribute>,
    ) -> Result<CreatedSession, SessionCreateError> {
        self.internal_state
            .lock()
            .await
            .create_session(
                users,
                title,
                host_address,
                public_open,
                private_open,
                public_filled,
                private_filled,
                attributes,
            )
            .await
    }

    pub async fn update_session(
        &self,
        users: Users,
        title: Title,
        session_id: KeyId,
        host_address: Addr,
        public_open: u32,
        private_open: u32,
        public_filled: u32,
        private_filled: u32,
        attributes: Vec<SearchAttribute>,
    ) -> Result<CreatedSession, SessionUpdateError> {
        self.internal_state
            .lock()
            .await
            .update_session(
                users,
                title,
                session_id,
                host_address,
                public_open,
                private_open,
                public_filled,
                private_filled,
                attributes,
            )
            .await
    }

    pub async fn close_session(&self) -> Result<(), SessionDeleteError> {
        todo!()
    }

    pub async fn search_for_sessions(
        &self,
        users: Users,
        title: Title,
        num_users: u16,
        flags: u16,
        max_results: usize,
        attributes: &[SearchAttribute],
    ) -> Result<Vec<SearchResult>, SessionSearchError> {
        self.internal_state
            .lock()
            .await
            .search_for_sessions(
                users,
                title,
                num_users,
                flags,
                max_results,
                attributes
            )
            .await
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Title {
    pub id: u32,
    pub ver: LibraryVersion,
}

#[derive(Debug)]
pub struct SearchResult {
    pub session_id: KeyId,
    pub host_address: Addr,
    pub key_exchange_key: SymmetricKey,
    pub public_open: u32,
    pub private_open: u32,
    pub public_filled: u32,
    pub private_filled: u32,
    pub attributes: Vec<SearchAttribute>,
}

#[derive(Debug)]
#[allow(dead_code)]
struct Session {
    session_id: KeyId,
    key_exchange_key: SymmetricKey,
    title: Title,
    host_users: Users,
    host_address: Addr,
    public_open: u32,
    private_open: u32,
    public_filled: u32,
    private_filled: u32,
    attributes: Vec<SearchAttribute>,
    creation_time: Instant,
}

struct InternalState {
    sessions: BTreeMap<KeyId, Session>,
    open_sessions: BTreeMap<Instant, KeyId>,
}

impl InternalState {
    fn new() -> Self {
        InternalState {
            sessions: BTreeMap::new(),
            open_sessions: BTreeMap::new(),
        }
    }

    #[allow(unused_variables)]
    async fn create_session(
        &mut self,
        users: Users,
        title: Title,
        host_address: Addr,
        public_open: u32,
        private_open: u32,
        public_filled: u32,
        private_filled: u32,
        attributes: Vec<SearchAttribute>,
    ) -> Result<CreatedSession, SessionCreateError> {
        let session_id = KeyId(rand::random());
        let key_exchange_key = SymmetricKey(rand::random());
        let creation_time = Instant::now();

        let session = Session {
            session_id,
            key_exchange_key,
            title,
            host_users: users,
            host_address,
            public_open,
            private_open,
            public_filled,
            private_filled,
            attributes,
            creation_time,
        };

        if self.sessions.contains_key(&session_id) {
            return Err(SessionCreateError::UnableToGenerateSessionId)
        }

        if self.open_sessions.contains_key(&creation_time) {
            error!("TODO: Too many back to back session creation requests: overlapping session create time");
            return Err(SessionCreateError::OverlappingCreationTime)
        }

        self.open_sessions.insert(creation_time, session_id);
        self.sessions.insert(session_id, session);

        Ok(CreatedSession {
            session_id,
            key_exchange_key,
        })
    }

    pub async fn update_session(
        &mut self,
        users: Users,
        title: Title,
        session_id: KeyId,
        host_address: Addr,
        public_open: u32,
        private_open: u32,
        public_filled: u32,
        private_filled: u32,
        attributes: Vec<SearchAttribute>,
    ) -> Result<CreatedSession, SessionUpdateError> {
        let existing_session = self.sessions.get_mut(&session_id)
            .ok_or(SessionUpdateError::SessionIdNotFound)?;

        if existing_session.host_users != users {
            return Err(SessionUpdateError::UserMismatch);
        }
        if existing_session.title != title {
            return Err(SessionUpdateError::TitleMismatch);
        }
        if existing_session.host_address != host_address {
            return Err(SessionUpdateError::HostAddressMismatch);
        }

        existing_session.public_open = public_open;
        existing_session.private_open = private_open;
        existing_session.public_filled = public_filled;
        existing_session.private_filled = private_filled;
        existing_session.attributes = attributes;

        Ok(CreatedSession {
            session_id: existing_session.session_id,
            key_exchange_key: existing_session.key_exchange_key,
        })
    }

    #[allow(unused_variables)]
    async fn search_for_sessions(
        &mut self,
        users: Users,
        title: Title,
        num_users: u16,
        flags: u16,
        max_results: usize,
        attributes: &[SearchAttribute],
    ) -> Result<Vec<SearchResult>, SessionSearchError> {
        let mut results = vec![];

        for (_, session) in self.sessions.iter() {
            if title == session.title {
                error!("TODO: compare attributes and user count");
                results.push(SearchResult {
                    session_id: session.session_id,
                    host_address: session.host_address,
                    key_exchange_key: session.key_exchange_key,
                    public_open: session.public_open,
                    private_open: session.private_open,
                    public_filled: session.public_filled,
                    private_filled: session.private_filled,
                    attributes: session.attributes.clone()
                })
            }

            if results.len() >= max_results {
                break;
            }
        }

        Ok(results)
    }
}