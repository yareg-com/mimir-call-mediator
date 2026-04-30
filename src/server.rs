use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::{Mutex, mpsc};
use tracing::{debug, info, trace, warn};

use crate::constants::*;
use crate::session::{PubKey, SessionId, SessionRegistry};

/// Stable ID for a control-stream connection. One per live reliable
/// connection; participants with multiple devices on the same pubkey
/// get distinct ControlIds.
pub type ControlId = u64;

/// Sender half of a control-stream writer task. Each control connection
/// has its own task that pulls from this channel and writes framed
/// messages to the peer, so everywhere else in the code can push to
/// clients without grabbing write locks on the underlying stream.
#[derive(Clone)]
pub struct ControlSender(pub mpsc::Sender<(u8, Vec<u8>)>);

impl ControlSender {
    pub async fn push(&self, cmd: u8, body: Vec<u8>) -> bool {
        self.0.send((cmd, body)).await.is_ok()
    }
}

pub struct ServerState {
    pub mediator_pub: [u8; 32],
    pub registry: Arc<SessionRegistry>,

    /// Live reliable-control connections keyed by ControlId.
    pub controls: Mutex<HashMap<ControlId, ControlSender>>,

    /// Authenticated pubkey for each live control connection. A client
    /// may have many controls (multi-device); a control belongs to
    /// exactly one pubkey (the one ygg_stream authenticated at handshake
    /// time).
    pub control_pub: Mutex<HashMap<ControlId, PubKey>>,

    /// For each (session, pubkey) we remember which ControlId owns the
    /// participant. Used to target PARTICIPANT_UPDATE pushes.
    pub member_control: Mutex<HashMap<(SessionId, PubKey), ControlId>>,

    next_control_id: AtomicU64,
}

impl ServerState {
    pub fn new(mediator_pub: [u8; 32], registry: Arc<SessionRegistry>) -> Arc<Self> {
        Arc::new(Self {
            mediator_pub,
            registry,
            controls: Mutex::new(HashMap::new()),
            control_pub: Mutex::new(HashMap::new()),
            member_control: Mutex::new(HashMap::new()),
            next_control_id: AtomicU64::new(1),
        })
    }

    pub fn next_control_id(&self) -> ControlId {
        self.next_control_id.fetch_add(1, Ordering::Relaxed)
    }
}

// ── Reliable-control accept loop ────────────────────────────────────────────

pub async fn run_control_accept_loop(state: Arc<ServerState>, node: Arc<ygg_stream::AsyncNode>) {
    info!("control listener on port {}", SERVER_PORT);
    loop {
        let conn = match node.accept(SERVER_PORT).await {
            Ok(c) => c,
            Err(e) => {
                warn!("control accept error: {}", e);
                continue;
            }
        };
        let cid = state.next_control_id();
        let remote_pub_bytes = conn.public_key();
        let remote_pub: [u8; 32] = match remote_pub_bytes.as_slice().try_into() {
            Ok(b) => b,
            Err(_) => {
                warn!("control accept: unexpected pubkey length {}", remote_pub_bytes.len());
                continue;
            }
        };
        debug!("control {}: connected from {}", cid, hex::encode(&remote_pub[..8]));

        let s = state.clone();
        tokio::spawn(async move {
            crate::control::serve_control(s, conn, cid, remote_pub).await;
        });
    }
}

// ── Datagram accept loop (SFU path) ─────────────────────────────────────────

pub async fn run_media_loop(state: Arc<ServerState>, node: Arc<ygg_stream::AsyncNode>) {
    let handle = node.handle();
    let mut dg = handle.listen_datagram(SERVER_PORT).await;
    info!("media listener on port {}", SERVER_PORT);

    static DG_TOTAL: AtomicU64 = AtomicU64::new(0);
    static DG_OVERSIZED: AtomicU64 = AtomicU64::new(0);
    static DG_UNKNOWN: AtomicU64 = AtomicU64::new(0);

    loop {
        let (data, sender) = match dg.recv().await {
            Ok(v) => v,
            Err(e) => {
                warn!("datagram recv error: {}", e);
                break;
            }
        };
        let total = DG_TOTAL.fetch_add(1, Ordering::Relaxed) + 1;
        if total == 1 {
            info!(
                "first datagram on port {}: bytes={} sender_ygg={}",
                SERVER_PORT,
                data.len(),
                hex::encode(sender.as_ref()),
            );
        } else if total % 500 == 0 {
            trace!("media listener: {} total datagrams", total);
        }
        if data.is_empty() {
            continue;
        }
        if data.len() > MAX_DATAGRAM {
            let n = DG_OVERSIZED.fetch_add(1, Ordering::Relaxed) + 1;
            if n == 1 || n % 100 == 0 {
                warn!("oversized datagram {}B from {} (#{}) — dropping", data.len(), hex::encode(sender.as_ref()), n);
            }
            continue;
        }
        match data[0] {
            DG_CALL_PACKET => {
                crate::media::handle_call_packet(&state, &handle, &sender, &data).await;
            }
            other => {
                let n = DG_UNKNOWN.fetch_add(1, Ordering::Relaxed) + 1;
                if n == 1 || n % 100 == 0 {
                    warn!("unknown datagram type 0x{:02X} from {} (#{})", other, hex::encode(sender.as_ref()), n);
                }
            }
        }
    }
}
