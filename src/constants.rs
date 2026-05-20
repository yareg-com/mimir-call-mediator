// Wire protocol version
pub const VERSION: u8 = 1;

// ygg_stream port used for both reliable control stream and media datagrams.
// ygg_stream multiplexes datagrams and streams on the same port number.
pub const SERVER_PORT: u16 = 70;

// Key file for the mediator's Ed25519 identity key
pub const KEY_FILE: &str = "/var/lib/mimir-call-mediator/generated.key";

// Control-plane command codes (reliable stream)
pub const CMD_HELLO: u8 = 0x01;          // client → server: version probe
pub const CMD_HELLO_ACK: u8 = 0x02;      // server → client
pub const CMD_CALL_CREATE: u8 = 0x10;    // client → server
pub const CMD_CALL_CREATE_ACK: u8 = 0x11;
pub const CMD_CALL_JOIN: u8 = 0x12;
pub const CMD_CALL_JOIN_ACK: u8 = 0x13;
pub const CMD_CALL_LEAVE: u8 = 0x14;
pub const CMD_CALL_PARTICIPANT_UPDATE: u8 = 0x20; // server → clients, full list
pub const CMD_CALL_PARTICIPANT_EVENT: u8 = 0x21;  // server → clients, single join/leave
pub const CMD_ERROR: u8 = 0x7F;

// Media-plane datagram type byte (first byte of every datagram payload)
pub const DG_CALL_PACKET: u8 = 0x01;

// Response status
pub const STATUS_OK: u8 = 0x00;
pub const STATUS_ERR: u8 = 0x01;

// Error codes
pub const ERR_UNKNOWN_SESSION: u8 = 0x01;
pub const ERR_NOT_A_MEMBER: u8 = 0x02;
pub const ERR_SESSION_FULL: u8 = 0x03;
pub const ERR_BAD_SIGNATURE: u8 = 0x04;
pub const ERR_MODE_UNSUPPORTED: u8 = 0x05;
pub const ERR_MALFORMED: u8 = 0x06;

// Participant-event sub-types
pub const EVT_JOINED: u8 = 0x01;
pub const EVT_LEFT: u8 = 0x02;

// Call session modes
pub const MODE_SFU: u8 = 0x00; // server forwards encrypted ciphertext
pub const MODE_MCU: u8 = 0x01; // server decodes + mixes + re-encodes (plaintext audio)

// Session ID: 16 alphanumeric chars → 16 bytes on the wire
pub const SESSION_ID_LEN: usize = 16;

// Limits
pub const MAX_DISPLAY_NAME_LEN: usize = 64;
pub const MAX_ASC_LEN: usize = 64; // AAC AudioSpecificConfig is tiny (~2-5 bytes typical)
pub const MAX_PARTICIPANTS: usize = 16; // v1 cap
pub const MAX_CONTROL_FRAME: u32 = 64 * 1024;
pub const MAX_DATAGRAM: usize = 4 * 1024; // AAC 20ms mono ≪ 1500, pair-redundant ≪ 3000

// Timers
pub const EMPTY_SESSION_TTL_SECS: u64 = 5 * 60; // kill empty sessions after 5 min
pub const SESSION_GC_INTERVAL_SECS: u64 = 30;
