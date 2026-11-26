//! An in-process FUSE connection.
//!
//! It takes the place of `/dev/fuse` for a session whose requests are made inside the process,
//! by the SMB server, rather than by a kernel. The session reads requests and writes replies
//! through it exactly as it would through the device, and each reply is handed to the caller
//! waiting for its `unique`.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::io;
use std::io::IoSlice;
use std::sync::Condvar;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::mpsc;
use std::time::Duration;
use std::time::Instant;

use nix::errno::Errno;

use crate::ll::fuse_abi::fuse_out_header;

#[derive(Debug, Default)]
struct State {
    /// Requests the session has not read yet
    requests: VecDeque<Vec<u8>>,
    /// Who waits for the reply to each unique
    pending: HashMap<u64, mpsc::SyncSender<Vec<u8>>>,
    /// When the session last read a request or sent a reply
    last_progress: Option<Instant>,
    closed: bool,
}

/// The two ends of an in-process FUSE connection
#[derive(Debug, Default)]
pub(crate) struct Transport {
    state: Mutex<State>,
    request_ready: Condvar,
}

impl Transport {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // A panic elsewhere leaves the queue itself consistent
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// The session's end: wait for the next request, as read(2) on `/dev/fuse` does. Once the
    /// connection is closed this fails with `ENODEV`, which ends the session as an unmount does.
    pub(crate) fn receive(&self, buffer: &mut [u8]) -> nix::Result<usize> {
        let mut state = self.lock();
        loop {
            if state.closed {
                return Err(Errno::ENODEV);
            }
            if let Some(request) = state.requests.pop_front() {
                state.last_progress = Some(Instant::now());
                let Some(dest) = buffer.get_mut(..request.len()) else {
                    // Callers keep requests within the negotiated sizes, so this is a bug.
                    // Fail the one request, as dropping its reply sender does, and go on
                    log::error!(
                        "in-process FUSE request of {} bytes is too large",
                        request.len()
                    );
                    if let Some(unique) = unique_of(&request) {
                        state.pending.remove(&unique);
                    }
                    continue;
                };
                dest.copy_from_slice(&request);
                return Ok(request.len());
            }
            state = self
                .request_ready
                .wait(state)
                .unwrap_or_else(|poison| poison.into_inner());
        }
    }

    /// The session's end: deliver a reply, as writev(2) on `/dev/fuse` does
    pub(crate) fn send(&self, bufs: &[IoSlice<'_>]) -> io::Result<()> {
        let reply: Vec<u8> = bufs.iter().flat_map(|buf| buf.iter().copied()).collect();
        let unique =
            unique_of(&reply).ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
        if unique == 0 {
            // A notification: nothing here caches what one would invalidate
            return Err(io::Error::from_raw_os_error(libc::ENOSYS));
        }
        let mut state = self.lock();
        state.last_progress = Some(Instant::now());
        let waiter = state.pending.remove(&unique);
        drop(state);
        match waiter {
            // The caller may have given up already; that is no error of the session's
            Some(waiter) => {
                let _ = waiter.send(reply);
                Ok(())
            }
            // As the kernel answers a reply to a request it does not know
            None => Err(io::Error::from_raw_os_error(libc::ENOENT)),
        }
    }

    /// The caller's end: queue `request`, whose header carries `unique`, and return where its
    /// reply arrives. The receiver fails if the connection closes before the reply comes.
    pub(crate) fn request(
        &self,
        unique: u64,
        request: Vec<u8>,
    ) -> Result<mpsc::Receiver<Vec<u8>>, crate::Errno> {
        let (sender, receiver) = mpsc::sync_channel(1);
        let mut state = self.lock();
        if state.closed {
            return Err(crate::Errno::ENOTCONN);
        }
        if state.pending.is_empty() && state.requests.is_empty() {
            // Stall detection measures from the oldest unanswered request
            state.last_progress = Some(Instant::now());
        }
        state.pending.insert(unique, sender);
        state.requests.push_back(request);
        drop(state);
        self.request_ready.notify_one();
        Ok(receiver)
    }

    /// Whether requests have waited `timeout` with the session neither reading one nor
    /// replying: it is no longer serving them
    #[cfg_attr(not(fuser_mount_impl = "smb"), allow(dead_code))]
    pub(crate) fn stalled(&self, timeout: Duration) -> bool {
        let state = self.lock();
        let waiting = !state.pending.is_empty() || !state.requests.is_empty();
        waiting
            && state
                .last_progress
                .is_some_and(|last| last.elapsed() >= timeout)
    }

    /// End the connection: the session's next receive fails with `ENODEV`, and requests
    /// still waiting for a reply fail
    pub(crate) fn close(&self) {
        let mut state = self.lock();
        state.closed = true;
        state.requests.clear();
        state.pending.clear();
        drop(state);
        self.request_ready.notify_all();
    }
}

/// The `unique` of a request or reply: both headers carry it at the same offset
fn unique_of(message: &[u8]) -> Option<u64> {
    const OFFSET: usize = std::mem::offset_of!(fuse_out_header, unique);
    let bytes = message.get(OFFSET..OFFSET + 8)?;
    Some(u64::from_ne_bytes(bytes.try_into().ok()?))
}

#[cfg(test)]
mod test {
    use super::*;

    fn header(unique: u64) -> Vec<u8> {
        let mut message = vec![0u8; 16];
        message[8..16].copy_from_slice(&unique.to_ne_bytes());
        message
    }

    #[test]
    fn replies_reach_their_callers() {
        let transport = Transport::new();
        let first = transport.request(7, header(7)).unwrap();
        let second = transport.request(8, header(8)).unwrap();
        let mut buffer = [0u8; 64];
        assert_eq!(transport.receive(&mut buffer).unwrap(), 16);
        assert_eq!(unique_of(&buffer), Some(7));
        assert_eq!(transport.receive(&mut buffer).unwrap(), 16);
        assert_eq!(unique_of(&buffer), Some(8));

        // Out of order, as a session that answers later may
        transport.send(&[IoSlice::new(&header(8))]).unwrap();
        transport.send(&[IoSlice::new(&header(7))]).unwrap();
        assert_eq!(unique_of(&first.recv().unwrap()), Some(7));
        assert_eq!(unique_of(&second.recv().unwrap()), Some(8));

        // A reply to nothing, and a notification
        let err = transport.send(&[IoSlice::new(&header(9))]).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ENOENT));
        let err = transport.send(&[IoSlice::new(&header(0))]).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ENOSYS));
    }

    #[test]
    fn close_ends_both_sides() {
        let transport = Transport::new();
        let waiting = transport.request(1, header(1)).unwrap();
        transport.close();
        assert!(waiting.recv().is_err());
        assert_eq!(transport.receive(&mut [0u8; 64]), Err(Errno::ENODEV));
        assert_eq!(
            transport.request(2, header(2)).unwrap_err(),
            crate::Errno::ENOTCONN
        );
    }

    #[test]
    fn unanswered_requests_stall() {
        let transport = Transport::new();
        assert!(!transport.stalled(Duration::ZERO));
        let _waiting = transport.request(1, header(1)).unwrap();
        assert!(transport.stalled(Duration::ZERO));
        assert!(!transport.stalled(Duration::from_secs(60)));
    }
}
