// SFU media path: parse a CALL_PACKET datagram, verify session
// membership, fan out verbatim to all other participants. Zero decode.
//
// Note on impersonation: clients advertise their permanent Ed25519
// identity in `from_pubkey`, but Yggdrasil routing uses a different
// ephemeral keypair, so `sender_addr` (= ygg routing addr) can't be
// compared against `Addr::from(from_pubkey)`. Insider-forgery prevention
// would require capturing the ephemeral-addr per (session, member) at
// CALL_JOIN time and matching that here. Until that plumbing lands, we
// rely on: (a) session-membership check on `from_pubkey`, (b) AEAD with
// a session-scoped key — outsiders can't even produce ciphertext.
//
// MCU mode is rejected at session creation (see session.rs), so any
// CALL_PACKET reaching this path is SFU.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tracing::{debug, info, warn};
use ygg_stream::{Addr, ConnectHandle};

use crate::constants::*;
use crate::protocol::parse_call_packet;
use crate::server::ServerState;
use crate::session::CallMode;

// Per-reason packet counters. We don't want to log every packet (50/s per
// sender), so we count each drop/forward reason and emit the first one plus
// every Nth occurrence.
static CNT_RX: AtomicU64 = AtomicU64::new(0);
static CNT_PARSE_FAIL: AtomicU64 = AtomicU64::new(0);
static CNT_UNKNOWN_SESSION: AtomicU64 = AtomicU64::new(0);
static CNT_NOT_MEMBER: AtomicU64 = AtomicU64::new(0);
static CNT_MCU: AtomicU64 = AtomicU64::new(0);
static CNT_FORWARD: AtomicU64 = AtomicU64::new(0);
static CNT_NO_TARGETS: AtomicU64 = AtomicU64::new(0);

const LOG_EVERY: u64 = 100;

fn should_log(counter: &AtomicU64) -> (bool, u64) {
    let n = counter.fetch_add(1, Ordering::Relaxed) + 1;
    (n == 1 || n % LOG_EVERY == 0, n)
}

pub async fn handle_call_packet(
    state: &Arc<ServerState>,
    handle: &ConnectHandle,
    sender_addr: &Addr,
    data: &[u8],
) {
    let (log_rx, n_rx) = should_log(&CNT_RX);
    if log_rx {
        debug!(
            "CALL_PACKET rx #{} from ygg={} bytes={}",
            n_rx,
            hex::encode(sender_addr.as_ref()),
            data.len(),
        );
    }

    let hdr = match parse_call_packet(data) {
        Ok(h) => h,
        Err(e) => {
            let (log, n) = should_log(&CNT_PARSE_FAIL);
            if log {
                warn!("parse_call_packet failed (#{}): {}", n, e);
            }
            return;
        }
    };

    let session = match state.registry.get(hdr.session_id).await {
        Some(s) => s,
        None => {
            let (log, n) = should_log(&CNT_UNKNOWN_SESSION);
            if log {
                warn!(
                    "unknown session {} from {} (#{})",
                    hex::encode(&hdr.session_id[..6]),
                    hex::encode(&hdr.from_pubkey[..4]),
                    n,
                );
            }
            return;
        }
    };

    // Collect `(identity, ygg_addr)` for every session member other than the
    // sender. `identity` is used for logging; `ygg_addr` is what we actually
    // need to route the forwarded datagram.
    let (is_member, targets): (bool, Vec<([u8; 32], [u8; 32])>) = {
        let ps = session.participants.read().await;
        let member = ps.contains_key(hdr.from_pubkey);
        let t = if member {
            ps.values()
                .filter(|p| &p.pubkey != hdr.from_pubkey)
                .map(|p| (p.pubkey, p.ygg_pubkey))
                .collect()
        } else {
            Vec::new()
        };
        (member, t)
    };
    if !is_member {
        let (log, n) = should_log(&CNT_NOT_MEMBER);
        if log {
            warn!(
                "non-member {} sent CALL_PACKET on session {} (#{})",
                hex::encode(&hdr.from_pubkey[..4]),
                hex::encode(&hdr.session_id[..6]),
                n,
            );
        }
        return;
    }

    match session.mode {
        CallMode::Sfu => {
            let target_count = targets.len();
            if target_count == 0 {
                let (log, n) = should_log(&CNT_NO_TARGETS);
                if log {
                    debug!(
                        "no peers to forward to on session {} from {} (#{})",
                        hex::encode(&hdr.session_id[..6]),
                        hex::encode(&hdr.from_pubkey[..4]),
                        n,
                    );
                }
                return;
            }

            let (log_fwd, n_fwd) = should_log(&CNT_FORWARD);
            if log_fwd {
                info!(
                    "fwd #{} {}B from {} sid={} seq={} -> {} peers",
                    n_fwd,
                    data.len(),
                    hex::encode(&hdr.from_pubkey[..4]),
                    hex::encode(&hdr.session_id[..6]),
                    hdr.seq,
                    target_count,
                );
            }

            for (identity, ygg) in targets {
                let addr = Addr::from(ygg);
                let data_owned = data.to_vec();
                let h = handle.clone();
                let target_hex = hex::encode(&identity[..4]);
                tokio::spawn(async move {
                    match h.send_datagram(&addr, SERVER_PORT, data_owned).await {
                        Ok(_) => {}
                        Err(e) => warn!("send_datagram to {} failed: {}", target_hex, e),
                    }
                });
            }
        }
        CallMode::Mcu => {
            let (log, n) = should_log(&CNT_MCU);
            if log {
                warn!("MCU packet (#{}) — unreachable", n);
            }
        }
    }
}
