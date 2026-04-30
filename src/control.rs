// Reliable control-stream handler: one task per connection.
//
// ygg_stream::AsyncConn is Clone-based rather than split-based, so we
// clone the conn for the writer task and keep the original for reads.
// All outbound frames go through an mpsc queue consumed by the writer,
// which lets handlers push frames without owning the connection.

use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::constants::*;
use crate::protocol::{encode_control_frame, read_control_frame};
use crate::server::{ControlId, ControlSender, ServerState};

pub async fn serve_control(
    state: Arc<ServerState>,
    conn: ygg_stream::AsyncConn,
    cid: ControlId,
    remote_pub: [u8; 32],
) {
    let (tx, mut rx) = mpsc::channel::<(u8, Vec<u8>)>(64);
    let sender = ControlSender(tx);
    state.controls.lock().await.insert(cid, sender.clone());
    state.control_pub.lock().await.insert(cid, remote_pub);

    // Writer task: owns a clone of the conn, drains the queue.
    let writer_conn = conn.clone();
    let writer_cid = cid;
    let writer_task = tokio::spawn(async move {
        while let Some((cmd, body)) = rx.recv().await {
            let frame = encode_control_frame(cmd, &body);
            if let Err(e) = writer_conn.write(&frame).await {
                debug!("control {} writer error: {}", writer_cid, e);
                break;
            }
        }
    });

    // Read loop.
    loop {
        let (cmd, body) = match read_control_frame(&conn).await {
            Ok(v) => v,
            Err(e) => {
                debug!("control {} read ended: {}", cid, e);
                break;
            }
        };
        if let Err(e) =
            crate::handlers::dispatch(&state, cid, &remote_pub, cmd, &body, &sender).await
        {
            warn!("control {} handler error (cmd 0x{:02X}): {}", cid, cmd, e);
            let err_body = crate::protocol::build_error(ERR_MALFORMED, &e);
            let _ = sender.push(CMD_ERROR, err_body).await;
        }
    }

    // Cleanup.
    state.controls.lock().await.remove(&cid);
    state.control_pub.lock().await.remove(&cid);
    crate::handlers::on_control_disconnect(&state, cid, &remote_pub).await;

    drop(sender);
    let _ = writer_task.await;
    conn.abort().await;
    debug!("control {} closed", cid);
}
