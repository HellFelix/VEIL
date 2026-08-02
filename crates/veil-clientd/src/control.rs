//! Placeholder framing for the control stream.
//!
//! `plan.md` §6.1 gives the control stream length-prefixed `postcard` frames
//! carrying `ClientMsg`/`ServerMsg`, designed at M3. Until those types exist
//! this carries one short UTF-8 string per frame, in the same direction of
//! travel: the client speaks first, the server answers. Only the payload is
//! provisional, the shape is not.
//!
//! Duplicated in `veild` on purpose. Both copies are deleted at M3 when
//! `veil-proto` owns the codec, and a shared placeholder protocol would be
//! harder to remove than two throwaway ones.

use quinn::{RecvStream, SendStream};

/// Largest frame accepted, in bytes.
///
/// Small on purpose: the length prefix is attacker-controlled, so it bounds an
/// allocation before the allocation happens.
const MAX_FRAME: usize = 1024;

/// Writes one length-prefixed frame.
pub async fn write_frame(stream: &mut SendStream, text: &str) -> Result<(), String> {
    let body = text.as_bytes();

    let len = u16::try_from(body.len()).map_err(|_| format!("frame too long: {}", body.len()))?;

    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| e.to_string())?;

    stream.write_all(body).await.map_err(|e| e.to_string())
}

/// Reads one length-prefixed frame.
///
/// Every failure is an error rather than a panic: these bytes come from the
/// peer, and invariant 7 forbids a panic reachable from a control message.
pub async fn read_frame(stream: &mut RecvStream) -> Result<String, String> {
    let mut prefix = [0u8; 2];
    stream
        .read_exact(&mut prefix)
        .await
        .map_err(|e| e.to_string())?;

    let len = usize::from(u16::from_be_bytes(prefix));
    if len > MAX_FRAME {
        return Err(format!("frame of {len} bytes exceeds the {MAX_FRAME} limit"));
    }

    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .await
        .map_err(|e| e.to_string())?;

    String::from_utf8(body).map_err(|e| e.to_string())
}
