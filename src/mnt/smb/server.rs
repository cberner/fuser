//! SMB over TCP (MS-SMB2 2.1): each message framed by a zero byte and a 24-bit length. Each
//! connection's messages are answered in turn, on a thread of its own.

use std::io;
use std::io::BufReader;
use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use log::debug;
use log::warn;

use super::smb2::Connection;
use super::smb2::MAX_IO;
use super::smb2::Share;

/// The largest message taken: a compound with a write of `MAX_IO`, and room for the rest
const MAX_MESSAGE: usize = 4 * MAX_IO as usize;

/// Reads one message. Session keep-alives, which carry none, are skipped
pub(crate) fn read_message(input: &mut impl Read) -> io::Result<Vec<u8>> {
    loop {
        let mut header = [0; 4];
        input.read_exact(&mut header)?;
        let len = u32::from_be_bytes([0, header[1], header[2], header[3]]) as usize;
        if len > MAX_MESSAGE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SMB message too large",
            ));
        }
        let mut message = vec![0; len];
        input.read_exact(&mut message)?;
        if header[0] == 0 {
            return Ok(message);
        }
    }
}

pub(crate) fn write_message(output: &mut impl Write, message: &[u8]) -> io::Result<()> {
    let mut buf = Vec::with_capacity(4 + message.len());
    buf.extend_from_slice(&(message.len() as u32).to_be_bytes());
    buf.extend_from_slice(message);
    output.write_all(&buf)
}

#[derive(Debug, Default)]
struct Stop {
    stopped: AtomicBool,
    connections: Mutex<Vec<Arc<TcpStream>>>,
}

impl Stop {
    fn connections(&self) -> std::sync::MutexGuard<'_, Vec<Arc<TcpStream>>> {
        self.connections
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

/// Stops a running `Server`
#[derive(Debug, Clone)]
pub(crate) struct Stopper {
    stop: Arc<Stop>,
    addr: SocketAddr,
}

impl Stopper {
    /// Stops accepting connections, and ends those open
    pub(crate) fn stop(&self) {
        if self.stop.stopped.swap(true, Ordering::SeqCst) {
            return;
        }
        for stream in self.stop.connections().drain(..) {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        // Wakes the accept
        let _ = TcpStream::connect(self.addr);
    }
}

/// An SMB server for one share, on 127.0.0.1
#[derive(Debug)]
pub(crate) struct Server {
    listener: TcpListener,
    share: Arc<Share>,
    stop: Arc<Stop>,
}

impl Server {
    /// Listens on an ephemeral port, answering only once `run`
    pub(crate) fn bind(share: Share) -> io::Result<Self> {
        Ok(Server {
            listener: TcpListener::bind("127.0.0.1:0")?,
            share: Arc::new(share),
            stop: Arc::default(),
        })
    }

    pub(crate) fn addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub(crate) fn stopper(&self) -> io::Result<Stopper> {
        Ok(Stopper {
            stop: self.stop.clone(),
            addr: self.addr()?,
        })
    }

    /// Serves until stopped
    pub(crate) fn run(&self) {
        for stream in self.listener.incoming() {
            if self.stop.stopped.load(Ordering::SeqCst) {
                break;
            }
            let stream = match stream {
                Ok(stream) => Arc::new(stream),
                Err(err) => {
                    warn!("SMB server: accepting a connection failed: {err}");
                    continue;
                }
            };
            let _ = stream.set_nodelay(true);
            self.stop.connections().push(stream.clone());
            let (share, stop) = (self.share.clone(), self.stop.clone());
            let spawned = std::thread::Builder::new()
                .name("fuser-smb-conn".to_owned())
                .spawn(move || {
                    serve(&share, &stream);
                    stop.connections().retain(|s| !Arc::ptr_eq(s, &stream));
                });
            if let Err(err) = spawned {
                warn!("SMB server: no thread for a connection: {err}");
            }
        }
        debug!("SMB server stopped");
    }
}

/// Answers one connection's messages until it closes, then closes what it left open
fn serve(share: &Share, stream: &TcpStream) {
    let mut connection = Connection::new(share);
    let mut input = BufReader::new(stream);
    loop {
        let message = match read_message(&mut input) {
            Ok(message) => message,
            Err(err) => {
                if err.kind() != io::ErrorKind::UnexpectedEof {
                    debug!("SMB server: connection ended: {err}");
                }
                break;
            }
        };
        let Some(reply) = connection.answer(&message) else {
            debug!("SMB server: ending a connection that sent what is not SMB 2");
            break;
        };
        if !reply.is_empty() {
            if let Err(err) = write_message(&mut &*stream, &reply) {
                debug!("SMB server: replying failed: {err}");
                break;
            }
        }
    }
    connection.close_all();
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn framing() {
        let mut input = Vec::new();
        // A keep-alive, then a message
        input.extend_from_slice(&[0x85, 0, 0, 0]);
        write_message(&mut input, b"hello").unwrap();
        assert_eq!(&input[4..8], [0, 0, 0, 5]);
        let mut input = &input[..];
        assert_eq!(read_message(&mut input).unwrap(), b"hello");
        assert!(read_message(&mut input).is_err());
        let too_large = (MAX_MESSAGE as u32 + 1).to_be_bytes();
        assert!(read_message(&mut &too_large[..]).is_err());
    }
}
