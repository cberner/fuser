//! An in-process stand-in for `/dev/fuse`.
//!
//! The NFS server plays the kernel's part: it queues FUSE requests here, which the session reads
//! as it would read the device, and the session's replies are routed back to whoever is waiting
//! for the request with the same `unique`.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::io;
use std::io::IoSlice;
use std::sync::mpsc;

use nix::errno::Errno;
use parking_lot::Condvar;
use parking_lot::Mutex;
use zerocopy::IntoBytes;

use crate::ll::fuse_abi::fuse_in_header;
use crate::ll::fuse_abi::fuse_opcode;

/// Who a request is made on behalf of
#[derive(Debug, Clone, Copy)]
pub(crate) struct Caller {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
}

#[derive(Debug, Default)]
struct State {
    requests: VecDeque<Vec<u8>>,
    pending: HashMap<u64, mpsc::SyncSender<Vec<u8>>>,
    next_unique: u64,
    /// Requests submitted so far
    submitted: u64,
    closed: bool,
    /// Set by `fail`: the session then ends with an error rather than as an unmount would
    failed: bool,
}

/// A FUSE connection within the process
#[derive(Debug, Default)]
pub(crate) struct Transport {
    state: Mutex<State>,
    readable: Condvar,
}

impl Transport {
    /// Queues a request and returns where its reply will arrive. Fails with `ENOTCONN` once the
    /// connection has been closed
    pub(crate) fn submit(
        &self,
        opcode: fuse_opcode,
        nodeid: u64,
        caller: Caller,
        args: &[&[u8]],
    ) -> Result<mpsc::Receiver<Vec<u8>>, Errno> {
        let len = size_of::<fuse_in_header>() + args.iter().map(|a| a.len()).sum::<usize>();
        let mut state = self.state.lock();
        if state.closed {
            return Err(Errno::ENOTCONN);
        }
        state.next_unique += 1;
        state.submitted += 1;
        let unique = state.next_unique;
        let header = fuse_in_header {
            len: u32::try_from(len).map_err(|_| Errno::E2BIG)?,
            opcode: opcode as u32,
            unique,
            nodeid,
            uid: caller.uid,
            gid: caller.gid,
            // No process to name: the NFS client does not say which one is asking
            pid: 0,
            padding: 0,
        };
        let mut request = Vec::with_capacity(len);
        request.extend_from_slice(header.as_bytes());
        for arg in args {
            request.extend_from_slice(arg);
        }
        let (sender, receiver) = mpsc::sync_channel(1);
        state.pending.insert(unique, sender);
        state.requests.push_back(request);
        drop(state);
        self.readable.notify_one();
        Ok(receiver)
    }

    /// What reading `/dev/fuse` does: blocks until a request is queued. Once the connection is
    /// closed, the requests still queued are delivered, then `ENODEV`, which ends the session
    /// as an unmount would, or `EIO` after `fail`
    pub(crate) fn receive(&self, buffer: &mut [u8]) -> nix::Result<usize> {
        let mut state = self.state.lock();
        loop {
            if let Some(request) = state.requests.pop_front() {
                let Some(dest) = buffer.get_mut(..request.len()) else {
                    // The session sizes its buffer for the largest write it negotiated, and
                    // writes are split to fit
                    log::error!(
                        "FUSE request of {} bytes does not fit the {} byte buffer",
                        request.len(),
                        buffer.len()
                    );
                    return Err(Errno::EIO);
                };
                dest.copy_from_slice(&request);
                return Ok(request.len());
            }
            if state.closed {
                return Err(if state.failed {
                    Errno::EIO
                } else {
                    Errno::ENODEV
                });
            }
            self.readable.wait(&mut state);
        }
    }

    /// What writing `/dev/fuse` does: hands a reply to whoever waits for it. Notifications,
    /// which have no request, are dropped: the NFS client caches by its own rules and cannot be
    /// told to invalidate anything
    pub(crate) fn send(&self, bufs: &[IoSlice<'_>]) -> io::Result<()> {
        let reply: Vec<u8> = bufs.iter().flat_map(|b| b.iter().copied()).collect();
        let Some(unique) = reply.get(8..16) else {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        };
        let unique = u64::from_ne_bytes(unique.try_into().expect("8 bytes"));
        if unique == 0 {
            return Ok(());
        }
        let sender = self.state.lock().pending.remove(&unique);
        if let Some(sender) = sender {
            // Room for the one reply, so this does not block
            let _ = sender.send(reply);
        }
        Ok(())
    }

    /// Ends the connection. Requests already queued are still delivered, but their replies go
    /// nowhere, and requests still waiting for one see it fail
    pub(crate) fn close(&self) {
        let mut state = self.state.lock();
        state.closed = true;
        state.pending.clear();
        drop(state);
        self.readable.notify_all();
    }

    /// Ends the connection as `close` does, but so that the session reports an error
    #[cfg_attr(
        any(not(fuser_mount_impl = "nfs"), fuser_nfs_serve_only),
        allow(dead_code)
    )]
    pub(crate) fn fail(&self) {
        self.state.lock().failed = true;
        self.close();
    }

    /// How many requests have been submitted
    #[cfg_attr(
        any(not(fuser_mount_impl = "nfs"), fuser_nfs_serve_only),
        allow(dead_code)
    )]
    pub(crate) fn submitted(&self) -> u64 {
        self.state.lock().submitted
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.state.lock().closed
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const CALLER: Caller = Caller { uid: 1, gid: 2 };

    #[test]
    fn replies_reach_the_request_with_the_same_unique() {
        let transport = Transport::default();
        let first = transport
            .submit(fuse_opcode::FUSE_GETATTR, 7, CALLER, &[b"ab"])
            .unwrap();
        let second = transport
            .submit(fuse_opcode::FUSE_LOOKUP, 1, CALLER, &[b"x", b"\0"])
            .unwrap();

        let mut buf = [0u8; 128];
        let n = transport.receive(&mut buf).unwrap();
        assert_eq!(n, 42);
        let header = &buf[..40];
        assert_eq!(u32::from_ne_bytes(header[0..4].try_into().unwrap()), 42);
        assert_eq!(
            u32::from_ne_bytes(header[4..8].try_into().unwrap()),
            fuse_opcode::FUSE_GETATTR as u32
        );
        let unique1 = u64::from_ne_bytes(header[8..16].try_into().unwrap());
        assert_eq!(u64::from_ne_bytes(header[16..24].try_into().unwrap()), 7);
        assert_eq!(u32::from_ne_bytes(header[24..28].try_into().unwrap()), 1);
        assert_eq!(u32::from_ne_bytes(header[28..32].try_into().unwrap()), 2);
        assert_eq!(&buf[40..42], b"ab");

        let n = transport.receive(&mut buf).unwrap();
        assert_eq!(&buf[40..n], b"x\0");
        let unique2 = u64::from_ne_bytes(buf[8..16].try_into().unwrap());
        assert_ne!(unique1, unique2);

        // Answer out of order
        let mut reply = [0u8; 16];
        reply[8..16].copy_from_slice(&unique2.to_ne_bytes());
        transport.send(&[IoSlice::new(&reply)]).unwrap();
        assert!(first.try_recv().is_err());
        assert_eq!(second.try_recv().unwrap(), reply);

        // Notifications and replies nobody waits for are dropped
        transport.send(&[IoSlice::new(&[0u8; 16])]).unwrap();
        transport.send(&[IoSlice::new(&reply)]).unwrap();
    }

    #[test]
    fn close_drains_then_ends_the_session() {
        let transport = Transport::default();
        let waiting = transport
            .submit(fuse_opcode::FUSE_DESTROY, 0, CALLER, &[])
            .unwrap();
        transport.close();
        assert_eq!(
            transport
                .submit(fuse_opcode::FUSE_GETATTR, 1, CALLER, &[])
                .unwrap_err(),
            Errno::ENOTCONN
        );
        // The waiter learns that no reply will come
        assert_eq!(
            waiting.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Disconnected)
        );
        let mut buf = [0u8; 64];
        assert_eq!(transport.receive(&mut buf).unwrap(), 40);
        assert_eq!(transport.receive(&mut buf).unwrap_err(), Errno::ENODEV);

        let transport = Transport::default();
        transport.fail();
        assert_eq!(transport.receive(&mut buf).unwrap_err(), Errno::EIO);
    }

    #[test]
    fn receive_waits_for_a_request() {
        let transport = std::sync::Arc::new(Transport::default());
        let reader = {
            let transport = transport.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 64];
                transport.receive(&mut buf)
            })
        };
        std::thread::sleep(std::time::Duration::from_millis(20));
        let _reply = transport
            .submit(fuse_opcode::FUSE_GETATTR, 1, CALLER, &[])
            .unwrap();
        assert_eq!(reader.join().unwrap(), Ok(40));
    }
}
