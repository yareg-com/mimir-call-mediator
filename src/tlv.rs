// TLV framing — same shape as mimir-mediator / mimir-tracker.
// u8 tag, varint length (<= 28 bits), raw bytes.

use std::collections::HashMap;
use std::io::{self, Write};

// Call-mediator TLV tag space. Kept distinct from mediator/tracker spaces
// on purpose so a stray message from the wrong protocol can't accidentally
// parse into something meaningful.
pub const TAG_SESSION_ID: u8 = 0x01;
pub const TAG_PUBKEY: u8 = 0x02;
pub const TAG_SIGNATURE: u8 = 0x03;
pub const TAG_DISPLAY_NAME: u8 = 0x04;
pub const TAG_MODE: u8 = 0x05;
pub const TAG_AUDIO_CONFIG: u8 = 0x06; // AAC AudioSpecificConfig bytes
pub const TAG_SAMPLE_RATE: u8 = 0x07;
pub const TAG_CHANNELS: u8 = 0x08;
pub const TAG_PARTICIPANT: u8 = 0x09; // nested TLV
pub const TAG_EVENT_TYPE: u8 = 0x0A;
pub const TAG_ERROR_CODE: u8 = 0x0B;
pub const TAG_ERROR_MSG: u8 = 0x0C;
pub const TAG_CREATED_AT: u8 = 0x0D;
pub const TAG_JOINED_AT: u8 = 0x0E;
/// Permanent Ed25519 identity pubkey advertised by the client in CALL_JOIN.
/// The control-stream authenticates with the client's ephemeral Yggdrasil
/// routing key; this tag lets the server key sessions by the stable identity
/// (which is what datagram `from_pubkey` carries) while still remembering the
/// ygg addr for forwarding.
pub const TAG_IDENTITY_PUBKEY: u8 = 0x0F;

pub type TlvMap = HashMap<u8, Vec<u8>>;
pub type TlvMultiMap = HashMap<u8, Vec<Vec<u8>>>;

pub fn write_varint<W: Write>(w: &mut W, mut value: u32) -> io::Result<()> {
    for _ in 0..4 {
        let mut b = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            b |= 0x80;
        }
        w.write_all(&[b])?;
        if value == 0 {
            return Ok(());
        }
    }
    Err(io::Error::new(io::ErrorKind::InvalidData, "varint overflow"))
}

fn read_varint_from_bytes(data: &[u8], offset: usize) -> io::Result<(u32, usize)> {
    let mut result: u32 = 0;
    let mut shift: u32 = 0;
    for i in 0..4 {
        if offset + i >= data.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "varint: unexpected end"));
        }
        let b = data[offset + i];
        result |= ((b & 0x7F) as u32) << shift;
        if (b & 0x80) == 0 {
            return Ok((result, i + 1));
        }
        shift += 7;
    }
    Err(io::Error::new(io::ErrorKind::InvalidData, "varint overflow"))
}

pub fn write_tlv<W: Write>(w: &mut W, tag: u8, value: &[u8]) -> io::Result<()> {
    w.write_all(&[tag])?;
    write_varint(w, value.len() as u32)?;
    if !value.is_empty() {
        w.write_all(value)?;
    }
    Ok(())
}

pub fn parse_tlvs(payload: &[u8]) -> io::Result<TlvMap> {
    let mut result = TlvMap::new();
    let mut offset = 0;
    while offset < payload.len() {
        let tag = payload[offset];
        offset += 1;
        let (length, consumed) = read_varint_from_bytes(payload, offset)?;
        offset += consumed;
        let length = length as usize;
        if offset + length > payload.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("tag 0x{:02X} length {} exceeds payload bounds", tag, length),
            ));
        }
        result.insert(tag, payload[offset..offset + length].to_vec());
        offset += length;
    }
    Ok(result)
}

#[allow(dead_code)]
pub fn parse_tlvs_multi(payload: &[u8]) -> io::Result<TlvMultiMap> {
    let mut result = TlvMultiMap::new();
    let mut offset = 0;
    while offset < payload.len() {
        let tag = payload[offset];
        offset += 1;
        let (length, consumed) = read_varint_from_bytes(payload, offset)?;
        offset += consumed;
        let length = length as usize;
        if offset + length > payload.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("tag 0x{:02X} length {} exceeds payload bounds", tag, length),
            ));
        }
        result.entry(tag).or_default().push(payload[offset..offset + length].to_vec());
        offset += length;
    }
    Ok(result)
}

pub fn tlv_get_bytes<'a>(m: &'a TlvMap, tag: u8, expected: usize) -> Result<&'a [u8], String> {
    let v = m.get(&tag).ok_or_else(|| format!("missing tag 0x{:02X}", tag))?;
    if expected > 0 && v.len() != expected {
        return Err(format!("tag 0x{:02X}: expected {} bytes, got {}", tag, expected, v.len()));
    }
    Ok(v)
}

pub fn tlv_get_u8(m: &TlvMap, tag: u8) -> Result<u8, String> {
    let v = tlv_get_bytes(m, tag, 1)?;
    Ok(v[0])
}

pub fn tlv_get_u32(m: &TlvMap, tag: u8) -> Result<u32, String> {
    let v = tlv_get_bytes(m, tag, 4)?;
    Ok(u32::from_be_bytes(v.try_into().unwrap()))
}

pub fn tlv_get_u64(m: &TlvMap, tag: u8) -> Result<u64, String> {
    let v = tlv_get_bytes(m, tag, 8)?;
    Ok(u64::from_be_bytes(v.try_into().unwrap()))
}

pub fn tlv_get_string(m: &TlvMap, tag: u8) -> Result<String, String> {
    let v = m.get(&tag).ok_or_else(|| format!("missing tag 0x{:02X}", tag))?;
    String::from_utf8(v.clone()).map_err(|e| format!("tag 0x{:02X}: invalid utf8: {}", tag, e))
}

pub fn tlv_encode_bytes<W: Write>(w: &mut W, tag: u8, v: &[u8]) -> io::Result<()> { write_tlv(w, tag, v) }
pub fn tlv_encode_u8<W: Write>(w: &mut W, tag: u8, v: u8) -> io::Result<()> { write_tlv(w, tag, &[v]) }
pub fn tlv_encode_u32<W: Write>(w: &mut W, tag: u8, v: u32) -> io::Result<()> { write_tlv(w, tag, &v.to_be_bytes()) }
pub fn tlv_encode_u64<W: Write>(w: &mut W, tag: u8, v: u64) -> io::Result<()> { write_tlv(w, tag, &v.to_be_bytes()) }
pub fn tlv_encode_string<W: Write>(w: &mut W, tag: u8, v: &str) -> io::Result<()> { write_tlv(w, tag, v.as_bytes()) }

pub fn build_tlv_payload<F>(build: F) -> io::Result<Vec<u8>>
where F: FnOnce(&mut Vec<u8>) -> io::Result<()>,
{
    let mut buf = Vec::new();
    build(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tlv_roundtrip() {
        let mut buf = Vec::new();
        tlv_encode_u8(&mut buf, TAG_MODE, 0x01).unwrap();
        tlv_encode_string(&mut buf, TAG_DISPLAY_NAME, "alice").unwrap();
        tlv_encode_bytes(&mut buf, TAG_SESSION_ID, b"0123456789abcdef").unwrap();
        let m = parse_tlvs(&buf).unwrap();
        assert_eq!(tlv_get_u8(&m, TAG_MODE).unwrap(), 0x01);
        assert_eq!(tlv_get_string(&m, TAG_DISPLAY_NAME).unwrap(), "alice");
        assert_eq!(tlv_get_bytes(&m, TAG_SESSION_ID, 16).unwrap(), b"0123456789abcdef");
    }
}
