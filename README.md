# mimir-call-mediator

A small, opinionated **group audio call mediator** for the [Mimir](https://github.com/Mimir-IM) ecosystem.
It listens on a single [ygg_stream](https://github.com/Revertron/ygg_stream) port and shuffles call
control messages and AAC-encoded audio between participants reachable over the
[Yggdrasil](https://yggdrasil-network.github.io/) network.

The mediator is currently **SFU-only** (Selective Forwarding Unit): it does not
decode or mix audio — it just forwards each participant's encrypted packets to
every other participant in the same session. An MCU mode is reserved on the
wire (`MODE_MCU = 0x01`) but disabled in this build.

## Features

- Group calls with up to **16 participants** per session (`MAX_PARTICIPANTS`).
- One `ygg_stream` port (default `70`) carries **both** the reliable control
  stream and the unreliable media datagrams.
- Stable Ed25519 identity per mediator instance, persisted to
  `call_mediator.key`. Generated on first run.
- Sessions are addressed by random 16-byte IDs, hex-printable.
- Empty sessions are garbage-collected after 5 minutes (`EMPTY_SESSION_TTL_SECS`).
- Zero codec work in the server: the SFU forwards bytes verbatim, so AEAD-
  encrypted client payloads stay opaque to the mediator.

## Building

Requires a recent stable Rust toolchain (edition 2024).

```bash
cargo build --release
```

## Running

The mediator needs at least one Yggdrasil peer URI to bootstrap its node:

```bash
./target/release/mimir-call-mediator \
    --peer tls://example.peer.host:12345 \
    --peer tls://another.peer:23456
```

`--peer` (`-p`) is repeatable. On startup the binary prints its public key,
which clients use to address it.

Logging defaults are sensible for production. Override with `RUST_LOG`, e.g.
`RUST_LOG=mimir_call_mediator=trace`.

### Command-line options

| Flag           | Description                                     |
|----------------|-------------------------------------------------|
| `-p`, `--peer` | Yggdrasil peer URI (repeatable, at least one)   |
| `-h`, `--help` | Print usage                                     |

## Wire protocol

Two channels share the same `ygg_stream` port:

**Control stream (reliable):**

```
[u8 version][u8 cmd][u32 BE length][TLV payload...]
```

**Media datagrams (unreliable):**

```
[u8 type=0x01][u8 version][session_id 16][from_pubkey 32][u32 BE seq][payload...]
```

Control payloads use the same TLV shape as the rest of the Mimir
protocols — `u8 tag`, varint length, raw value bytes — but with a distinct
tag space so misrouted frames cannot accidentally parse.

### Control commands (v1)

| Code | Name                       | Direction        |
|------|----------------------------|------------------|
| 0x01 | `HELLO`                    | client → server  |
| 0x02 | `HELLO_ACK`                | server → client  |
| 0x10 | `CALL_CREATE`              | client → server  |
| 0x11 | `CALL_CREATE_ACK`          | server → client  |
| 0x12 | `CALL_JOIN`                | client → server  |
| 0x13 | `CALL_JOIN_ACK`            | server → client  |
| 0x14 | `CALL_LEAVE`               | client → server  |
| 0x20 | `CALL_PARTICIPANT_UPDATE`  | server → client  |
| 0x21 | `CALL_PARTICIPANT_EVENT`   | server → client  |
| 0x7F | `ERROR`                    | server → client  |

### Authentication and identity

A client's `ygg_stream` connection authenticates an **ephemeral Yggdrasil
routing key**, not its long-term identity. To make membership and forwarding
work, the client advertises its **permanent Ed25519 pubkey** in `CALL_JOIN`
(tag `TAG_IDENTITY_PUBKEY = 0x0F`). The server keys its participant map by
that identity and remembers the ephemeral routing key separately for
addressing forwarded datagrams.

The current SFU enforces *session membership* on incoming media (a non-member
cannot inject into a session). Insider impersonation across members is not
yet pinned to the routing key — see the comment at the top of `src/media.rs`.

## Project layout

```
src/
├── main.rs        — entry point, ygg_stream node setup, signal handling
├── server.rs      — accept loops for control streams and media datagrams
├── control.rs     — per-connection control reader/writer task
├── handlers.rs    — control-command dispatch (CREATE/JOIN/LEAVE/etc.)
├── media.rs       — SFU forwarding path
├── session.rs     — sessions, participants, GC of empty sessions
├── protocol.rs    — frame and datagram codec + typed payload builders
├── tlv.rs         — TLV tag space + encode/decode helpers
└── constants.rs   — protocol constants, command codes, limits
```

## Status

Pre-1.0. The wire format is versioned (`VERSION = 1`); breaking changes will
bump it. MCU mode, replay/sequence enforcement, and ephemeral-routing-key
pinning are tracked but not implemented.

## License

[MPL-2.0](https://www.mozilla.org/en-US/MPL/2.0/).
