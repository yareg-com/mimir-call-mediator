// Wire format helpers for the call-mediator.
//
// Control frames (over reliable ygg_stream::AsyncConn):
//     [u8 version][u8 cmd][u32 be length][TLV payload ...]
//
// Datagrams (over ygg_stream datagram channel):
//     [u8 type][u8 version][session_id 16][from_pubkey 32][u32 be seq][payload...]
//
// The control-frame layout mirrors mimir-mediator's shape; the datagram
// header is bespoke because datagrams are self-delimiting.
//
// AsyncConn is clone-based and exposes its own `read_with_timeout` / `write`
// methods rather than tokio::io traits, so we reproduce read_exact on top
// of read_with_timeout here.

use ygg_stream::AsyncConn;

use crate::constants::*;
use crate::tlv::*;

pub const DATAGRAM_HEADER_LEN: usize = 1 /*type*/ + 1 /*version*/ + SESSION_ID_LEN + 32 /*pubkey*/ + 4 /*seq*/;

// ── Reliable control-stream framing ──────────────────────────────────────

const READ_TIMEOUT_MS: i64 = 300_000;

/// Read exactly `buf.len()` bytes from an AsyncConn, looping across
/// multiple read_with_timeout calls. Returns Err on close/timeout.
pub async fn read_exact(conn: &AsyncConn, buf: &mut [u8]) -> Result<(), String> {
    let mut off = 0;
    while off < buf.len() {
        match conn.read_with_timeout(&mut buf[off..], READ_TIMEOUT_MS).await {
            Ok(0) => return Err("connection closed".to_string()),
            Ok(n) => off += n,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Read one control frame. Returns (cmd, body).
pub async fn read_control_frame(conn: &AsyncConn) -> Result<(u8, Vec<u8>), String> {
    let mut hdr = [0u8; 6];
    read_exact(conn, &mut hdr).await?;
    if hdr[0] != VERSION {
        return Err(format!("bad version {}", hdr[0]));
    }
    let cmd = hdr[1];
    let len = u32::from_be_bytes([hdr[2], hdr[3], hdr[4], hdr[5]]);
    if len > MAX_CONTROL_FRAME {
        return Err(format!("control frame too large: {}", len));
    }
    let mut body = vec![0u8; len as usize];
    if len > 0 {
        read_exact(conn, &mut body).await?;
    }
    Ok((cmd, body))
}

/// Encode a framed control message into a Vec<u8> ready for the writer
/// task to `conn.write`. Pure function so callers can prepare frames
/// without holding locks.
pub fn encode_control_frame(cmd: u8, body: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(6 + body.len());
    buf.push(VERSION);
    buf.push(cmd);
    buf.extend_from_slice(&(body.len() as u32).to_be_bytes());
    buf.extend_from_slice(body);
    buf
}

// ── Datagram framing ─────────────────────────────────────────────────────

pub struct CallPacketHeader<'a> {
    pub session_id: &'a [u8; SESSION_ID_LEN],
    pub from_pubkey: &'a [u8; 32],
    pub seq: u32,
    pub payload: &'a [u8],
}

pub fn parse_call_packet(buf: &[u8]) -> Result<CallPacketHeader<'_>, &'static str> {
    if buf.len() < DATAGRAM_HEADER_LEN {
        return Err("datagram too short");
    }
    if buf[0] != DG_CALL_PACKET {
        return Err("wrong datagram type");
    }
    if buf[1] != VERSION {
        return Err("wrong version");
    }
    let session_id: &[u8; SESSION_ID_LEN] = (&buf[2..2 + SESSION_ID_LEN]).try_into().unwrap();
    let pk_start = 2 + SESSION_ID_LEN;
    let from_pubkey: &[u8; 32] = (&buf[pk_start..pk_start + 32]).try_into().unwrap();
    let seq_start = pk_start + 32;
    let seq = u32::from_be_bytes([
        buf[seq_start],
        buf[seq_start + 1],
        buf[seq_start + 2],
        buf[seq_start + 3],
    ]);
    let payload = &buf[DATAGRAM_HEADER_LEN..];
    Ok(CallPacketHeader { session_id, from_pubkey, seq, payload })
}

#[allow(dead_code)]
pub fn write_call_packet_header(
    out: &mut Vec<u8>,
    session_id: &[u8; SESSION_ID_LEN],
    from_pubkey: &[u8; 32],
    seq: u32,
) {
    out.reserve(DATAGRAM_HEADER_LEN);
    out.push(DG_CALL_PACKET);
    out.push(VERSION);
    out.extend_from_slice(session_id);
    out.extend_from_slice(from_pubkey);
    out.extend_from_slice(&seq.to_be_bytes());
}

// ── Typed control payload builders (server-side) ─────────────────────────

pub fn build_error(code: u8, msg: &str) -> Vec<u8> {
    build_tlv_payload(|w| {
        tlv_encode_u8(w, TAG_ERROR_CODE, code)?;
        if !msg.is_empty() {
            tlv_encode_string(w, TAG_ERROR_MSG, msg)?;
        }
        Ok(())
    })
    .unwrap_or_default()
}

pub fn build_create_ack(session_id: &[u8; SESSION_ID_LEN], mode: u8, created_at: i64) -> Vec<u8> {
    build_tlv_payload(|w| {
        tlv_encode_bytes(w, TAG_SESSION_ID, session_id)?;
        tlv_encode_u8(w, TAG_MODE, mode)?;
        tlv_encode_u64(w, TAG_CREATED_AT, created_at as u64)?;
        Ok(())
    })
    .unwrap_or_default()
}

pub fn build_join_ack(session_id: &[u8; SESSION_ID_LEN], mode: u8) -> Vec<u8> {
    build_tlv_payload(|w| {
        tlv_encode_bytes(w, TAG_SESSION_ID, session_id)?;
        tlv_encode_u8(w, TAG_MODE, mode)?;
        Ok(())
    })
    .unwrap_or_default()
}

pub struct ParticipantView<'a> {
    pub pubkey: &'a [u8; 32],
    pub display_name: &'a str,
    pub audio_config: &'a [u8],
    pub joined_at: i64,
}

pub fn build_participant_update(
    session_id: &[u8; SESSION_ID_LEN],
    participants: &[ParticipantView<'_>],
) -> Vec<u8> {
    build_tlv_payload(|w| {
        tlv_encode_bytes(w, TAG_SESSION_ID, session_id)?;
        for p in participants {
            let inner = build_tlv_payload(|iw| {
                tlv_encode_bytes(iw, TAG_PUBKEY, p.pubkey)?;
                tlv_encode_string(iw, TAG_DISPLAY_NAME, p.display_name)?;
                if !p.audio_config.is_empty() {
                    tlv_encode_bytes(iw, TAG_AUDIO_CONFIG, p.audio_config)?;
                }
                tlv_encode_u64(iw, TAG_JOINED_AT, p.joined_at as u64)?;
                Ok(())
            })?;
            tlv_encode_bytes(w, TAG_PARTICIPANT, &inner)?;
        }
        Ok(())
    })
    .unwrap_or_default()
}

pub fn build_participant_event(
    session_id: &[u8; SESSION_ID_LEN],
    event: u8,
    pubkey: &[u8; 32],
    display_name: &str,
) -> Vec<u8> {
    build_tlv_payload(|w| {
        tlv_encode_bytes(w, TAG_SESSION_ID, session_id)?;
        tlv_encode_u8(w, TAG_EVENT_TYPE, event)?;
        tlv_encode_bytes(w, TAG_PUBKEY, pubkey)?;
        tlv_encode_string(w, TAG_DISPLAY_NAME, display_name)?;
        Ok(())
    })
    .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datagram_roundtrip() {
        let sid = [7u8; SESSION_ID_LEN];
        let pk = [9u8; 32];
        let mut buf = Vec::new();
        write_call_packet_header(&mut buf, &sid, &pk, 12345);
        buf.extend_from_slice(b"AACPAYLOAD");
        let hdr = parse_call_packet(&buf).unwrap();
        assert_eq!(hdr.session_id, &sid);
        assert_eq!(hdr.from_pubkey, &pk);
        assert_eq!(hdr.seq, 12345);
        assert_eq!(hdr.payload, b"AACPAYLOAD");
    }

    #[test]
    fn datagram_too_short() {
        assert!(parse_call_packet(&[0u8; 10]).is_err());
    }

    #[test]
    fn datagram_wrong_type() {
        let mut buf = vec![0u8; DATAGRAM_HEADER_LEN];
        buf[0] = 0xEE;
        assert!(parse_call_packet(&buf).is_err());
    }

    #[test]
    fn control_frame_encode_shape() {
        let body = b"abc";
        let f = encode_control_frame(0x42, body);
        assert_eq!(f[0], VERSION);
        assert_eq!(f[1], 0x42);
        assert_eq!(u32::from_be_bytes([f[2], f[3], f[4], f[5]]), 3);
        assert_eq!(&f[6..], body);
    }
}
