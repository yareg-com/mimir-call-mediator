use std::sync::Arc;
use std::time::Instant;

use tracing::{debug, info};

use crate::constants::*;
use crate::protocol::*;
use crate::server::{ControlId, ControlSender, ServerState};
use crate::session::{CallMode, CallSession, Participant, PubKey, SessionId, now_unix};
use crate::tlv::*;

pub async fn dispatch(
    state: &Arc<ServerState>,
    cid: ControlId,
    remote_pub: &[u8; 32],
    cmd: u8,
    body: &[u8],
    sender: &ControlSender,
) -> Result<(), String> {
    match cmd {
        CMD_HELLO => handle_hello(sender).await,
        CMD_CALL_CREATE => handle_call_create(state, sender, body).await,
        CMD_CALL_JOIN => handle_call_join(state, cid, remote_pub, sender, body).await,
        CMD_CALL_LEAVE => handle_call_leave(state, cid, remote_pub, body).await,
        _ => Err(format!("unknown cmd 0x{:02X}", cmd)),
    }
}

async fn handle_hello(sender: &ControlSender) -> Result<(), String> {
    sender.push(CMD_HELLO_ACK, vec![VERSION]).await;
    Ok(())
}

async fn handle_call_create(
    state: &Arc<ServerState>,
    sender: &ControlSender,
    body: &[u8],
) -> Result<(), String> {
    let m = parse_tlvs(body).map_err(|e| format!("bad tlv: {}", e))?;
    let mode_byte = tlv_get_u8(&m, TAG_MODE)?;
    let mode = CallMode::from_wire(mode_byte).ok_or_else(|| format!("bad mode {}", mode_byte))?;

    match state.registry.create(mode).await {
        Ok(session) => {
            let ack = build_create_ack(&session.id, mode.to_wire(), session.created_at);
            sender.push(CMD_CALL_CREATE_ACK, ack).await;
        }
        Err(code) => {
            let err = build_error(code, "mode unsupported");
            sender.push(CMD_ERROR, err).await;
        }
    }
    Ok(())
}

async fn handle_call_join(
    state: &Arc<ServerState>,
    cid: ControlId,
    remote_pub: &[u8; 32],
    sender: &ControlSender,
    body: &[u8],
) -> Result<(), String> {
    let m = parse_tlvs(body).map_err(|e| format!("bad tlv: {}", e))?;
    let sid_bytes = tlv_get_bytes(&m, TAG_SESSION_ID, SESSION_ID_LEN)?;
    let session_id: SessionId = sid_bytes.try_into().unwrap();

    // Client must advertise its permanent identity so we can key the
    // participants map by the same pubkey that ends up in CALL_PACKET
    // `from_pubkey`. Older clients that predate this tag fall back to
    // remote_pub (ygg addr), which matches old behaviour — they'll still
    // hit the non-member drop, but at least won't break joins.
    let identity_pub: PubKey = match tlv_get_bytes(&m, TAG_IDENTITY_PUBKEY, 32) {
        Ok(b) => b.try_into().unwrap(),
        Err(_) => *remote_pub,
    };

    let display_name = tlv_get_string(&m, TAG_DISPLAY_NAME)
        .unwrap_or_else(|_| hex::encode(&identity_pub[..4]));
    if display_name.len() > MAX_DISPLAY_NAME_LEN {
        return Err("display name too long".into());
    }
    let audio_config = tlv_get_bytes(&m, TAG_AUDIO_CONFIG, 0)
        .map(|s| s.to_vec())
        .unwrap_or_default();
    if audio_config.len() > MAX_ASC_LEN {
        return Err("audio_config too long".into());
    }

    let session = match state.registry.get(&session_id).await {
        Some(s) => s,
        None => {
            let err = build_error(ERR_UNKNOWN_SESSION, "unknown session");
            sender.push(CMD_ERROR, err).await;
            return Ok(());
        }
    };

    {
        let mut ps = session.participants.write().await;
        if ps.len() >= MAX_PARTICIPANTS && !ps.contains_key(&identity_pub) {
            let err = build_error(ERR_SESSION_FULL, "session full");
            sender.push(CMD_ERROR, err).await;
            return Ok(());
        }
        ps.insert(
            identity_pub,
            Participant {
                pubkey: identity_pub,
                ygg_pubkey: *remote_pub,
                display_name: display_name.clone(),
                audio_config,
                joined_at: now_unix(),
                control_id: cid,
            },
        );
    }
    *session.empty_since.lock().await = None;
    state
        .member_control
        .lock()
        .await
        .insert((session_id, identity_pub), cid);

    info!(
        "session {} + id={} ygg={} (\"{}\") [cid={}]",
        hex::encode(&session_id[..6]),
        hex::encode(&identity_pub[..4]),
        hex::encode(&remote_pub[..4]),
        display_name,
        cid
    );

    let ack = build_join_ack(&session_id, session.mode.to_wire());
    sender.push(CMD_CALL_JOIN_ACK, ack).await;

    push_participant_update(state, &session, identity_pub).await;
    broadcast_event(state, &session, EVT_JOINED, &identity_pub, &display_name, None).await;
    Ok(())
}

async fn handle_call_leave(
    state: &Arc<ServerState>,
    cid: ControlId,
    _remote_pub: &[u8; 32],
    body: &[u8],
) -> Result<(), String> {
    let m = parse_tlvs(body).map_err(|e| format!("bad tlv: {}", e))?;
    let sid_bytes = tlv_get_bytes(&m, TAG_SESSION_ID, SESSION_ID_LEN)?;
    let session_id: SessionId = sid_bytes.try_into().unwrap();
    // A single control stream can (in principle) own multiple participant
    // records; find every (session, identity) owned by this cid in the
    // target session and drop them.
    let targets: Vec<PubKey> = {
        let mc = state.member_control.lock().await;
        mc.iter()
            .filter(|((s, _), v)| *s == session_id && **v == cid)
            .map(|((_, pk), _)| *pk)
            .collect()
    };
    for pk in targets {
        remove_member(state, &session_id, &pk, Some(cid)).await;
    }
    Ok(())
}

pub async fn on_control_disconnect(
    state: &Arc<ServerState>,
    cid: ControlId,
    _remote_pub: &[u8; 32],
) {
    let owned: Vec<(SessionId, PubKey)> = {
        let mc = state.member_control.lock().await;
        mc.iter()
            .filter(|(_, v)| **v == cid)
            .map(|((s, pk), _)| (*s, *pk))
            .collect()
    };
    for (sid, pk) in owned {
        remove_member(state, &sid, &pk, Some(cid)).await;
    }
}

async fn remove_member(
    state: &Arc<ServerState>,
    session_id: &SessionId,
    pubkey: &PubKey,
    only_if_owner_cid: Option<ControlId>,
) {
    let session = match state.registry.get(session_id).await {
        Some(s) => s,
        None => return,
    };

    {
        let mc = state.member_control.lock().await;
        if let (Some(want), Some(&have)) = (only_if_owner_cid, mc.get(&(*session_id, *pubkey))) {
            if have != want {
                return;
            }
        }
    }

    let (removed, display_name, became_empty) = {
        let mut ps = session.participants.write().await;
        let removed = ps.remove(pubkey);
        let became_empty = ps.is_empty();
        (
            removed.is_some(),
            removed.map(|p| p.display_name).unwrap_or_default(),
            became_empty,
        )
    };

    if !removed {
        return;
    }
    state
        .member_control
        .lock()
        .await
        .remove(&(*session_id, *pubkey));

    if became_empty {
        *session.empty_since.lock().await = Some(Instant::now());
    }

    info!(
        "session {} - {} (\"{}\")",
        hex::encode(&session_id[..6]),
        hex::encode(&pubkey[..4]),
        display_name
    );

    broadcast_event(state, &session, EVT_LEFT, pubkey, &display_name, None).await;
}

async fn push_participant_update(
    state: &Arc<ServerState>,
    session: &Arc<CallSession>,
    target_pub: PubKey,
) {
    let snapshot: Vec<_> = {
        let ps = session.participants.read().await;
        ps.values().cloned().collect()
    };
    let views: Vec<ParticipantView<'_>> = snapshot
        .iter()
        .map(|p| ParticipantView {
            pubkey: &p.pubkey,
            display_name: p.display_name.as_str(),
            audio_config: p.audio_config.as_slice(),
            joined_at: p.joined_at,
        })
        .collect();
    let body = build_participant_update(&session.id, &views);

    let cid = match state.member_control.lock().await.get(&(session.id, target_pub)) {
        Some(&c) => c,
        None => return,
    };
    let ctl = match state.controls.lock().await.get(&cid).cloned() {
        Some(c) => c,
        None => return,
    };
    ctl.push(CMD_CALL_PARTICIPANT_UPDATE, body).await;
}

async fn broadcast_event(
    state: &Arc<ServerState>,
    session: &Arc<CallSession>,
    event: u8,
    pubkey: &[u8; 32],
    display_name: &str,
    exclude_pub: Option<PubKey>,
) {
    let body = build_participant_event(&session.id, event, pubkey, display_name);
    let targets: Vec<ControlId> = {
        let ps = session.participants.read().await;
        let mc = state.member_control.lock().await;
        ps.keys()
            .filter(|pk| exclude_pub.as_ref() != Some(*pk))
            .filter_map(|pk| mc.get(&(session.id, *pk)).copied())
            .collect()
    };
    let ctls = state.controls.lock().await;
    for cid in targets {
        if let Some(ctl) = ctls.get(&cid).cloned() {
            let b = body.clone();
            tokio::spawn(async move {
                ctl.push(CMD_CALL_PARTICIPANT_EVENT, b).await;
            });
        }
    }
    debug!(
        "event {} for {} on session {}",
        event,
        hex::encode(&pubkey[..4]),
        hex::encode(&session.id[..6])
    );
}
