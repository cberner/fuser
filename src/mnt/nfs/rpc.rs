//! ONC RPC (RFC 5531) over TCP, for the NFS and MOUNT programs: record marking, call headers
//! and replies. Each connection's calls run on a few threads, as FUSE requests block.

use std::io;
use std::io::BufReader;
use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::mpsc;

use log::debug;
use log::warn;
use parking_lot::Mutex;

use super::nfs3::MAX_IO;
use super::nfs3::MOUNT_PROGRAM;
use super::nfs3::NFS_PROGRAM;
use super::nfs3::Nfs;
use super::nfs3::Refused;
use super::nfs3::VERSION;
use super::xdr::Reader;
use super::xdr::Writer;

const CALL: u32 = 0;
const REPLY: u32 = 1;
const MSG_ACCEPTED: u32 = 0;
const MSG_DENIED: u32 = 1;
// accept_stat
const SUCCESS: u32 = 0;
const PROG_UNAVAIL: u32 = 1;
const PROG_MISMATCH: u32 = 2;
const PROC_UNAVAIL: u32 = 3;
const GARBAGE_ARGS: u32 = 4;
/// reject_stat
const RPC_MISMATCH: u32 = 0;
/// The last fragment of a record
const LAST_FRAGMENT: u32 = 1 << 31;
/// The largest record taken: a WRITE of `MAX_IO`, with room for its headers
const MAX_RECORD: usize = MAX_IO as usize + 64 * 1024;
/// Threads answering the calls of one connection
const WORKERS: usize = 8;

/// Answers one RPC call message, returning the reply message. None for what is not a call
pub(crate) fn answer(nfs: &Nfs, call: &[u8]) -> Option<Vec<u8>> {
    let a = &mut Reader::new(call);
    let xid = a.u32().ok()?;
    if a.u32().ok()? != CALL {
        return None;
    }
    let mut out = Vec::new();
    out.put_u32(xid);
    out.put_u32(REPLY);
    if a.u32().ok()? != 2 {
        out.put_u32(MSG_DENIED);
        out.put_u32(RPC_MISMATCH);
        out.put_u32(2);
        out.put_u32(2);
        return Some(out);
    }
    let (program, version, procedure) = (a.u32().ok()?, a.u32().ok()?, a.u32().ok()?);
    // The credentials and verifier: requests are all made as the mounting user
    for _ in 0..2 {
        a.u32().ok()?;
        a.opaque().ok()?;
    }
    out.put_u32(MSG_ACCEPTED);
    // AUTH_NONE verifier
    out.put_u32(0);
    out.put_u32(0);
    let result = match program {
        NFS_PROGRAM | MOUNT_PROGRAM if version != VERSION => {
            out.put_u32(PROG_MISMATCH);
            out.put_u32(VERSION);
            out.put_u32(VERSION);
            return Some(out);
        }
        NFS_PROGRAM => nfs.nfs(procedure, a.rest()),
        MOUNT_PROGRAM => nfs.mount(procedure, a.rest()),
        _ => {
            out.put_u32(PROG_UNAVAIL);
            return Some(out);
        }
    };
    match result {
        Ok(results) => {
            out.put_u32(SUCCESS);
            out.extend_from_slice(&results);
        }
        Err(Refused::NoProcedure) => out.put_u32(PROC_UNAVAIL),
        Err(Refused::Garbage) => out.put_u32(GARBAGE_ARGS),
    }
    Some(out)
}

/// Reads one record, joining its fragments
pub(crate) fn read_record(input: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut record = Vec::new();
    loop {
        let mut header = [0; 4];
        input.read_exact(&mut header)?;
        let header = u32::from_be_bytes(header);
        let start = record.len();
        let len = (header & !LAST_FRAGMENT) as usize;
        if start + len > MAX_RECORD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "RPC record too large",
            ));
        }
        record.resize(start + len, 0);
        input.read_exact(&mut record[start..])?;
        if header & LAST_FRAGMENT != 0 {
            return Ok(record);
        }
    }
}

pub(crate) fn write_record(output: &mut impl Write, record: &[u8]) -> io::Result<()> {
    let mut buf = Vec::with_capacity(4 + record.len());
    // Replies are far below 2 GiB
    buf.extend_from_slice(&(record.len() as u32 | LAST_FRAGMENT).to_be_bytes());
    buf.extend_from_slice(record);
    output.write_all(&buf)
}

#[derive(Debug)]
struct Connection {
    stream: TcpStream,
    /// Held while a reply is written
    writing: Mutex<()>,
}

#[derive(Debug, Default)]
struct Stop {
    stopped: AtomicBool,
    connections: Mutex<Vec<Arc<Connection>>>,
}

/// Stops a running `Server`
#[derive(Debug, Clone)]
pub(crate) struct Stopper {
    stop: Arc<Stop>,
    addr: SocketAddr,
}

impl Stopper {
    /// Stops accepting connections and ends those open. Calls being answered are finished
    pub(crate) fn stop(&self) {
        if self.stop.stopped.swap(true, Ordering::SeqCst) {
            return;
        }
        for connection in self.stop.connections.lock().drain(..) {
            let _ = connection.stream.shutdown(std::net::Shutdown::Both);
        }
        // Wakes the accept
        let _ = TcpStream::connect(self.addr);
    }
}

/// An NFS server on 127.0.0.1
#[derive(Debug)]
pub(crate) struct Server {
    listener: TcpListener,
    nfs: Arc<Nfs>,
    stop: Arc<Stop>,
}

impl Server {
    /// Listens on `port` of 127.0.0.1, or an ephemeral one for 0, answering only once `run`
    pub(crate) fn bind(nfs: Nfs, port: u16) -> io::Result<Self> {
        Ok(Self {
            listener: TcpListener::bind(("127.0.0.1", port))?,
            nfs: Arc::new(nfs),
            stop: Arc::default(),
        })
    }

    #[cfg_attr(
        any(not(fuser_mount_impl = "nfs"), fuser_nfs_serve_only),
        allow(dead_code)
    )]
    pub(crate) fn port(&self) -> io::Result<u16> {
        Ok(self.listener.local_addr()?.port())
    }

    pub(crate) fn stopper(&self) -> io::Result<Stopper> {
        Ok(Stopper {
            stop: self.stop.clone(),
            addr: self.listener.local_addr()?,
        })
    }

    /// Serves until stopped
    pub(crate) fn run(&self) {
        for stream in self.listener.incoming() {
            if self.stop.stopped.load(Ordering::SeqCst) {
                break;
            }
            let stream = match stream {
                Ok(stream) => stream,
                Err(err) => {
                    warn!("NFS server: accepting a connection failed: {err}");
                    continue;
                }
            };
            let _ = stream.set_nodelay(true);
            let connection = Arc::new(Connection {
                stream,
                writing: Mutex::new(()),
            });
            self.stop.connections.lock().push(connection.clone());
            let nfs = self.nfs.clone();
            let stop = self.stop.clone();
            let spawned = std::thread::Builder::new()
                .name("fuser-nfs-conn".to_string())
                .spawn(move || {
                    serve(&nfs, &connection);
                    stop.connections
                        .lock()
                        .retain(|c| !Arc::ptr_eq(c, &connection));
                });
            if let Err(err) = spawned {
                warn!("NFS server: no thread for a connection: {err}");
            }
        }
        debug!("NFS server stopped");
    }
}

/// Reads one connection's calls, answering them on worker threads, until it closes
fn serve(nfs: &Arc<Nfs>, connection: &Arc<Connection>) {
    let (calls, queue) = mpsc::channel::<Vec<u8>>();
    let queue = Arc::new(Mutex::new(queue));
    for _ in 0..WORKERS {
        let (nfs, connection, queue) = (nfs.clone(), connection.clone(), queue.clone());
        let _ = std::thread::Builder::new()
            .name("fuser-nfs".to_string())
            .spawn(move || {
                loop {
                    // Not held while answering
                    let call = queue.lock().recv();
                    // Ends once the reader has gone and the queue is empty
                    let Ok(call) = call else {
                        return;
                    };
                    let Some(reply) = answer(&nfs, &call) else {
                        continue;
                    };
                    let _writing = connection.writing.lock();
                    if let Err(err) = write_record(&mut &connection.stream, &reply) {
                        debug!("NFS server: replying failed: {err}");
                    }
                }
            });
    }
    let mut input = BufReader::new(&connection.stream);
    loop {
        match read_record(&mut input) {
            Ok(call) => {
                if calls.send(call).is_err() {
                    return;
                }
            }
            Err(err) => {
                if err.kind() != io::ErrorKind::UnexpectedEof {
                    debug!("NFS server: connection ended: {err}");
                }
                return;
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn records_are_joined_from_fragments() {
        let mut input = Vec::new();
        input.extend_from_slice(&3u32.to_be_bytes());
        input.extend_from_slice(b"abc");
        input.extend_from_slice(&(2 | LAST_FRAGMENT).to_be_bytes());
        input.extend_from_slice(b"de");
        let mut output = Vec::new();
        write_record(&mut output, b"xy").unwrap();
        input.extend_from_slice(&output);
        let mut input = &input[..];
        assert_eq!(read_record(&mut input).unwrap(), b"abcde");
        assert_eq!(read_record(&mut input).unwrap(), b"xy");
        assert!(read_record(&mut input).is_err());
    }

    #[test]
    fn oversized_records_are_refused() {
        let header = ((MAX_RECORD as u32 + 1) | LAST_FRAGMENT).to_be_bytes();
        assert!(read_record(&mut &header[..]).is_err());
    }
}
