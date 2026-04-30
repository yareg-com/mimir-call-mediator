use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::{Mutex, RwLock};
use tracing::info;

use crate::constants::*;

pub type SessionId = [u8; SESSION_ID_LEN];
pub type PubKey = [u8; 32];

#[derive(Clone, Debug)]
pub struct Participant {
    /// Permanent Ed25519 identity pubkey — matches the `from_pubkey` in
    /// CALL_PACKET datagrams. This is the map key in `session.participants`.
    pub pubkey: PubKey,
    /// Ephemeral Yggdrasil routing pubkey — the `conn.public_key()` the
    /// control stream authenticated with. Used as `Addr::from(ygg_pubkey)`
    /// when forwarding datagrams to this participant.
    pub ygg_pubkey: PubKey,
    pub display_name: String,
    /// AAC AudioSpecificConfig bytes. Empty if the participant didn't
    /// send one (MCU mode, or a client that decides to piggyback the
    /// config inline with every packet instead).
    pub audio_config: Vec<u8>,
    pub joined_at: i64,
    /// Control-stream id that owns this participant record. If the
    /// owning stream drops, the participant is evicted.
    pub control_id: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallMode {
    Sfu,
    Mcu,
}

impl CallMode {
    pub fn from_wire(b: u8) -> Option<Self> {
        match b {
            MODE_SFU => Some(CallMode::Sfu),
            MODE_MCU => Some(CallMode::Mcu),
            _ => None,
        }
    }
    pub fn to_wire(self) -> u8 {
        match self {
            CallMode::Sfu => MODE_SFU,
            CallMode::Mcu => MODE_MCU,
        }
    }
}

pub struct CallSession {
    pub id: SessionId,
    pub mode: CallMode,
    pub created_at: i64,
    pub participants: RwLock<HashMap<PubKey, Participant>>,
    /// When the session last became empty. None while occupied. Used by
    /// the GC worker to drop empty sessions after EMPTY_SESSION_TTL_SECS.
    pub empty_since: Mutex<Option<Instant>>,
}

impl CallSession {
    pub fn new(id: SessionId, mode: CallMode) -> Arc<Self> {
        Arc::new(Self {
            id,
            mode,
            created_at: now_unix(),
            participants: RwLock::new(HashMap::new()),
            empty_since: Mutex::new(Some(Instant::now())),
        })
    }
}

pub struct SessionRegistry {
    inner: RwLock<HashMap<SessionId, Arc<CallSession>>>,
    pub mcu_enabled: bool,
}

impl SessionRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: RwLock::new(HashMap::new()),
            mcu_enabled: false,
        })
    }

    pub async fn create(&self, mode: CallMode) -> Result<Arc<CallSession>, u8> {
        if matches!(mode, CallMode::Mcu) && !self.mcu_enabled {
            return Err(ERR_MODE_UNSUPPORTED);
        }
        let id = generate_session_id();
        let session = CallSession::new(id, mode);
        self.inner.write().await.insert(id, session.clone());
        info!("session {} created (mode {:?})", hex::encode(&id[..6]), mode);
        Ok(session)
    }

    pub async fn get(&self, id: &SessionId) -> Option<Arc<CallSession>> {
        self.inner.read().await.get(id).cloned()
    }

    #[allow(dead_code)]
    pub async fn remove(&self, id: &SessionId) {
        if self.inner.write().await.remove(id).is_some() {
            info!("session {} removed", hex::encode(&id[..6]));
        }
    }

    pub async fn gc_empty(&self) {
        let ttl = Duration::from_secs(EMPTY_SESSION_TTL_SECS);
        let now = Instant::now();
        let mut doomed = Vec::new();
        {
            let map = self.inner.read().await;
            for (id, sess) in map.iter() {
                if let Some(t) = *sess.empty_since.lock().await {
                    if now.duration_since(t) >= ttl {
                        doomed.push(*id);
                    }
                }
            }
        }
        if !doomed.is_empty() {
            let mut map = self.inner.write().await;
            for id in doomed {
                if map.remove(&id).is_some() {
                    info!(
                        "session {} expired (empty > {}s)",
                        hex::encode(&id[..6]),
                        EMPTY_SESSION_TTL_SECS
                    );
                }
            }
        }
    }
}

pub async fn gc_loop(registry: Arc<SessionRegistry>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(SESSION_GC_INTERVAL_SECS));
    loop {
        ticker.tick().await;
        registry.gc_empty().await;
    }
}

pub fn generate_session_id() -> SessionId {
    use rand::RngCore;
    let mut id = [0u8; SESSION_ID_LEN];
    rand::thread_rng().fill_bytes(&mut id);
    id
}

pub fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}
