mod constants;
mod control;
mod handlers;
mod media;
mod protocol;
mod server;
mod session;
mod tlv;

use std::fs;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use tracing::{error, info};

use crate::constants::{KEY_FILE, SERVER_PORT};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new(
                    // Keep network-layer crates quiet, but surface our own debug
                    // output so media-forwarding diagnostics are visible without
                    // needing RUST_LOG on every run.
                    "info,mimir_call_mediator=debug,yggdrasil=info,ironwood=info,ygg_stream=info",
                )
            }),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    let mut opts = getopts::Options::new();
    opts.optmulti("p", "peer", "Yggdrasil peer URI (repeatable)", "URI");
    opts.optflag("h", "help", "Show help");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Error: {}", e);
            eprintln!("{}", opts.usage(&format!("Usage: {} [options]", args[0])));
            std::process::exit(1);
        }
    };

    if matches.opt_present("h") {
        println!("{}", opts.usage(&format!("Usage: {} [options]", args[0])));
        return;
    }

    let peers = matches.opt_strs("p");
    if peers.is_empty() {
        eprintln!("Error: at least one --peer is required");
        eprintln!("{}", opts.usage(&format!("Usage: {} [options]", args[0])));
        std::process::exit(1);
    }

    let signing_key = load_or_gen_key(KEY_FILE);
    let pub_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();
    info!("call-mediator pubkey: {}", hex::encode(&pub_bytes));

    let node = match ygg_stream::AsyncNode::new_with_key(signing_key.to_bytes().as_slice(), peers).await {
        Ok(n) => Arc::new(n),
        Err(e) => {
            error!("failed to start ygg_stream node: {}", e);
            std::process::exit(1);
        }
    };
    info!("ygg_stream node pubkey: {}", hex::encode(node.public_key()));

    let registry = session::SessionRegistry::new();
    let state = server::ServerState::new(pub_bytes, registry.clone());

    // Empty-session GC worker.
    let reg_gc = registry.clone();
    tokio::spawn(async move { session::gc_loop(reg_gc).await });

    info!("listening on port {}", SERVER_PORT);

    tokio::select! {
        _ = server::run_control_accept_loop(state.clone(), node.clone()) => {}
        _ = server::run_media_loop(state.clone(), node.clone()) => {}
        _ = tokio::signal::ctrl_c() => {
            info!("shutting down…");
        }
    }

    let _ = tokio::time::timeout(Duration::from_secs(2), node.close()).await;
}

fn load_or_gen_key(path: &str) -> SigningKey {
    if let Ok(data) = fs::read(path) {
        let seed: Option<[u8; 32]> = if data.len() == 32 {
            Some(data.try_into().unwrap())
        } else {
            let text = String::from_utf8_lossy(&data);
            let text = text.trim();
            if text.len() == 64 {
                hex::decode(text)
                    .ok()
                    .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            } else {
                None
            }
        };
        if let Some(seed) = seed {
            let key = SigningKey::from_bytes(&seed);
            info!("loaded key from {}, public: {}", path, hex::encode(key.verifying_key().as_bytes()));
            return key;
        }
    }
    let key = SigningKey::generate(&mut OsRng);
    if let Err(e) = fs::write(path, key.to_bytes()) {
        error!("failed to save key: {}", e);
    }
    info!("generated new key (saved to {}), public: {}", path, hex::encode(key.verifying_key().as_bytes()));
    key
}
