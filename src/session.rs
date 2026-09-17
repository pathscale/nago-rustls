//! The TLS loop: rustls driven over a byte stream.
//!
//! # Why there is no fork of rustls here
//!
//! rustls is already sans-io. [`read_tls`] takes ciphertext that arrived,
//! [`process_new_packets`] decrypts it, and [`write_tls`] hands back
//! ciphertext to send. None of it knows what a runtime is, so what is needed
//! on top is a loop rather than a rewrite, and this module is that loop.
//!
//! [`read_tls`]: rustls::ConnectionCommon::read_tls
//! [`write_tls`]: rustls::ConnectionCommon::write_tls
//! [`process_new_packets`]: rustls::ConnectionCommon::process_new_packets
//!
//! # Why it is generic over the stream
//!
//! Nothing here is specific to a socket. The loop needs somewhere to put
//! ciphertext and somewhere to get it from, which is two methods, so that is
//! what it asks for. A TCP socket satisfies it, and so would a Unix socket,
//! an in-memory pipe in a test, or another crate's stream entirely.
//!
//! # The shape of the loop
//!
//! Every operation is the same three steps in a ring: give rustls whatever
//! the stream produced, let it work, and send whatever it produced. The
//! subtlety is that either direction can block, and a handshake stalls if the
//! side that wants to write is not drained, so both are serviced on every
//! pass rather than only the one the caller asked about.

// The loop contains no `unsafe` of its own; all the cryptography and all the
// protocol handling is rustls'.
#![forbid(unsafe_code)]

use alloc::vec::Vec;
// rustls' plaintext ends are `std::io` types, so the traits have to be in
// scope to call them. rustls requires `std`, so this crate has it.
use std::io::{Read as _, Write as _};

use rustls::{ClientConnection, ServerConnection};

use crate::error::{codes, Result};
use crate::stream::ByteStream;

/// A TLS session over a byte stream.
///
/// Either end of the connection: the difference is only which rustls type is
/// inside, and every operation below is identical for both.
#[derive(Debug)]
pub struct TlsSession<S> {
    stream: S,
    session: Session,
    /// Plaintext rustls has decrypted but the caller has not taken yet.
    incoming: Vec<u8>,
    /// Where in `incoming` the caller has read up to.
    taken: usize,
}

/// Which side of the handshake this is.
#[derive(Debug)]
enum Session {
    Client(alloc::boxed::Box<ClientConnection>),
    Server(alloc::boxed::Box<ServerConnection>),
}

/// Dispatch a method to whichever session is inside.
///
/// rustls has no object-safe trait covering both directions, and the
/// alternative to this macro is writing every method twice.
macro_rules! session {
    // A single call: `session!(self, wants_write())`.
    ($self:expr, $method:ident($($argument:expr),*)) => {
        match &mut $self.session {
            Session::Client(session) => session.$method($($argument),*),
            Session::Server(session) => session.$method($($argument),*),
        }
    };
    // A call on what another call returned, which is how `reader()` and
    // `writer()` are reached: `session!(self, reader().read(buffer))`.
    ($self:expr, $outer:ident().$inner:ident($($argument:expr),*)) => {
        match &mut $self.session {
            Session::Client(session) => session.$outer().$inner($($argument),*),
            Session::Server(session) => session.$outer().$inner($($argument),*),
        }
    };
}

impl<S: ByteStream> TlsSession<S> {
    /// Start a client session over an already connected stream.
    pub fn client(stream: S, session: ClientConnection) -> Self {
        Self {
            stream,
            session: Session::Client(alloc::boxed::Box::new(session)),
            incoming: Vec::new(),
            taken: 0,
        }
    }

    /// Start a server session over an already accepted stream.
    pub fn server(stream: S, session: ServerConnection) -> Self {
        Self {
            stream,
            session: Session::Server(alloc::boxed::Box::new(session)),
            incoming: Vec::new(),
            taken: 0,
        }
    }

    /// Run the handshake to completion.
    ///
    /// Worth doing explicitly rather than letting the first read drive it: a
    /// certificate failure should surface at connect time, not as a strange
    /// error in the middle of the application's first message.
    pub async fn handshake(&mut self) -> Result<()> {
        while session!(self, is_handshaking()) {
            let wrote = self.flush_outgoing().await?;
            if !session!(self, is_handshaking()) {
                break;
            }
            // Only wait for the peer when there was nothing left to send:
            // reading first would deadlock a handshake whose next move is ours.
            if !wrote && self.fill_incoming().await? == 0 {
                return Err(codes::CONNECTION_RESET);
            }
        }
        // The last flight of the handshake is still in the buffer.
        self.flush_outgoing().await?;
        Ok(())
    }

    /// Send everything rustls currently wants to send.
    ///
    /// Returns whether anything went out, which the handshake loop uses to
    /// decide whether waiting on the peer is safe.
    async fn flush_outgoing(&mut self) -> Result<bool> {
        let mut sent = false;
        while session!(self, wants_write()) {
            let mut buffer = Vec::new();
            // Writing into a Vec cannot fail, so the error is a rustls state
            // problem rather than an I/O one.
            session!(self, write_tls(&mut buffer)).map_err(|_| codes::IO)?;
            if buffer.is_empty() {
                break;
            }
            self.stream.write_all(&buffer).await?;
            sent = true;
        }
        Ok(sent)
    }

    /// Read from the socket and let rustls decrypt.
    ///
    /// Returns how many ciphertext bytes arrived; zero means the peer closed.
    async fn fill_incoming(&mut self) -> Result<usize> {
        let mut chunk = [0u8; 16 * 1024];
        let read = self.stream.read(&mut chunk).await?;
        if read == 0 {
            return Ok(0);
        }

        let mut cursor = &chunk[..read];
        while !cursor.is_empty() {
            // `read_tls` takes as much as its internal buffer allows, which
            // may be less than offered, so this loops rather than assuming.
            let taken = session!(self, read_tls(&mut cursor)).map_err(|_| codes::IO)?;
            if taken == 0 {
                break;
            }
            let state = session!(self, process_new_packets())
                // A protocol error here is an attack or a broken peer; either
                // way the connection is finished.
                .map_err(|_| codes::PROTOCOL)?;

            let available = state.plaintext_bytes_to_read();
            if available > 0 {
                let start = self.incoming.len();
                self.incoming.resize(start + available, 0);
                // Reading plaintext out of rustls cannot fail once it has
                // reported the bytes are there.
                let _ = session!(self, reader().read(&mut self.incoming[start..]));
            }
        }
        Ok(read)
    }

    /// Read decrypted bytes into `buffer`.
    ///
    /// Returns zero when the peer has closed the session cleanly.
    pub async fn read(&mut self, buffer: &mut [u8]) -> Result<usize> {
        loop {
            // Serve what has already been decrypted before going to the socket.
            if self.taken < self.incoming.len() {
                let available = self.incoming.len() - self.taken;
                let take = available.min(buffer.len());
                buffer[..take].copy_from_slice(&self.incoming[self.taken..self.taken + take]);
                self.taken += take;

                // Reset rather than grow forever once drained.
                if self.taken == self.incoming.len() {
                    self.incoming.clear();
                    self.taken = 0;
                }
                return Ok(take);
            }

            // rustls may owe the peer a message even on a read: a key update
            // or an alert. Not sending it stalls the session.
            self.flush_outgoing().await?;

            if self.fill_incoming().await? == 0 {
                return Ok(0);
            }
        }
    }

    /// Write plaintext, encrypting and sending all of it.
    pub async fn write_all(&mut self, buffer: &[u8]) -> Result<()> {
        let mut written = 0;
        while written < buffer.len() {
            // rustls buffers the plaintext and encrypts on `write_tls`, so a
            // short accept here just means its buffer is full and needs
            // draining to the socket.
            let took = session!(self, writer().write(&buffer[written..])).map_err(|_| codes::IO)?;
            written += took;
            self.flush_outgoing().await?;
            if took == 0 {
                return Err(codes::IO);
            }
        }
        Ok(())
    }

    /// Send a close_notify and stop.
    ///
    /// Skipping this is what produces "connection reset" in a peer's logs
    /// instead of a clean end, and it is how a truncation attack is detected.
    pub async fn close(&mut self) -> Result<()> {
        session!(self, send_close_notify());
        self.flush_outgoing().await?;
        Ok(())
    }

    /// The negotiated ALPN protocol, if any.
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        match &self.session {
            Session::Client(session) => session.alpn_protocol(),
            Session::Server(session) => session.alpn_protocol(),
        }
    }

    /// The stream underneath, for a caller that needs its address.
    pub fn get_ref(&self) -> &S {
        &self.stream
    }
}

/// A TLS session is itself a byte stream, which is the whole point: a
/// WebSocket connection cannot tell whether it is speaking through one.
impl<S: ByteStream> ByteStream for TlsSession<S> {
    async fn read(&mut self, buffer: &mut [u8]) -> Result<usize> {
        Self::read(self, buffer).await
    }

    async fn write_all(&mut self, buffer: &[u8]) -> Result<()> {
        Self::write_all(self, buffer).await
    }
}

/// A client configuration trusting the usual roots.
#[cfg(feature = "webpki-roots")]
///
/// Uses the webpki bundle rather than the OS store: it is the same set every
/// other Rust TLS client in this house already trusts, and reading a system
/// store is a per-platform dependency this crate does not otherwise need.
#[must_use]
pub fn default_client_config() -> alloc::sync::Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    alloc::sync::Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::codes;
    use alloc::sync::Arc;
    use alloc::vec;
    use rustls::{ClientConnection, ServerConnection};
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
    use std::sync::mpsc::{Receiver, SyncSender};

    /// A self signed certificate for `localhost`, and a client config that
    /// trusts exactly it.
    ///
    /// Generated rather than committed: a checked-in certificate expires and
    /// then the suite fails for a reason unrelated to the code.
    fn certificate() -> (Arc<rustls::ServerConfig>, Arc<rustls::ClientConfig>) {
        let issued = rcgen::generate_simple_self_signed(["localhost".to_string()])
            .expect("generate certificate");
        let certificate = CertificateDer::from(issued.cert.der().to_vec());
        let key = PrivateKeyDer::try_from(issued.signing_key.serialize_der()).expect("private key");

        let server = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], key)
            .expect("server config");

        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).expect("trust the test certificate");
        let client = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        (Arc::new(server), Arc::new(client))
    }

    /// Two channels crossed over: what one end writes, the other reads.
    ///
    /// No socket and no runtime anywhere, which is the point of the trait.
    struct Pipe {
        outgoing: SyncSender<Vec<u8>>,
        incoming: Receiver<Vec<u8>>,
        pending: Vec<u8>,
    }

    impl ByteStream for Pipe {
        async fn read(&mut self, buffer: &mut [u8]) -> Result<usize> {
            while self.pending.is_empty() {
                // Bounded rather than a blocking recv. The two ends take turns
                // during a handshake, so a blocking wait here parks the thread
                // inside a poll and the test hangs forever instead of failing.
                // A timeout turns that into a visible failure.
                match self
                    .incoming
                    .recv_timeout(std::time::Duration::from_millis(500))
                {
                    Ok(chunk) => self.pending = chunk,
                    // The far end went away, or stopped talking: either way
                    // there is nothing more to read.
                    Err(_) => return Ok(0),
                }
            }
            let take = self.pending.len().min(buffer.len());
            buffer[..take].copy_from_slice(&self.pending[..take]);
            self.pending.drain(..take);
            Ok(take)
        }

        async fn write_all(&mut self, buffer: &[u8]) -> Result<()> {
            self.outgoing
                .send(buffer.to_vec())
                .map_err(|_| codes::BROKEN_PIPE)
        }
    }

    fn pipes() -> (Pipe, Pipe) {
        let (to_server, server_receives) = std::sync::mpsc::sync_channel(256);
        let (to_client, client_receives) = std::sync::mpsc::sync_channel(256);
        (
            Pipe {
                outgoing: to_server,
                incoming: client_receives,
                pending: Vec::new(),
            },
            Pipe {
                outgoing: to_client,
                incoming: server_receives,
                pending: Vec::new(),
            },
        )
    }

    /// Drive a future to completion on this thread.
    ///
    /// The crate has no runtime and does not want one, so the tests bring the
    /// smallest possible executor: poll until ready, parking in between.
    fn block_on<F: core::future::Future>(future: F) -> F::Output {
        use alloc::task::Wake;
        use core::task::{Context, Poll, Waker};

        struct Unparker(std::thread::Thread);
        impl Wake for Unparker {
            fn wake(self: Arc<Self>) {
                self.0.unpark();
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.0.unpark();
            }
        }

        let waker = Waker::from(Arc::new(Unparker(std::thread::current())));
        let mut context = Context::from_waker(&waker);
        let mut future = core::pin::pin!(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::park(),
            }
        }
    }

    #[test]
    fn a_session_carries_bytes_both_ways() {
        let (server_config, client_config) = certificate();
        let (client_pipe, server_pipe) = pipes();

        let server = std::thread::spawn(move || {
            let session = ServerConnection::new(server_config).expect("session");
            let mut tls = TlsSession::server(server_pipe, session);
            block_on(async move {
                tls.handshake().await.expect("handshake");
                let mut buffer = [0u8; 4];
                let read = tls.read(&mut buffer).await.expect("read");
                assert_eq!(&buffer[..read], b"ping");
                tls.write_all(b"pong").await.expect("write");
            });
        });

        let name = ServerName::try_from("localhost").expect("name");
        let session = ClientConnection::new(client_config, name).expect("session");
        let mut tls = TlsSession::client(client_pipe, session);
        block_on(async move {
            tls.handshake().await.expect("handshake");
            tls.write_all(b"ping").await.expect("write");
            let mut buffer = [0u8; 4];
            let read = tls.read(&mut buffer).await.expect("read");
            assert_eq!(&buffer[..read], b"pong");
        });

        server.join().expect("server thread");
    }

    #[test]
    fn a_payload_spanning_many_records_round_trips() {
        // Just past the 16 KiB record cap, which is all it takes to span
        // more than one and exercise the loop that reassembles them. Larger
        // measures the cipher rather than this crate.
        const SIZE: usize = 48 * 1024;
        let (server_config, client_config) = certificate();
        let (client_pipe, server_pipe) = pipes();

        // The server signals once it is past the handshake. Without this the
        // client can fill the channel with record after record while the
        // server is still exchanging handshake messages, and the send blocks
        // in a direction the peer is not reading.
        let (ready, started) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let session = ServerConnection::new(server_config).expect("session");
            let mut tls = TlsSession::server(server_pipe, session);
            block_on(async move {
                tls.handshake().await.expect("handshake");
                ready.send(()).expect("signal");
                let mut total = 0usize;
                let mut buffer = vec![0u8; 32 * 1024];
                while total < SIZE {
                    let read = tls.read(&mut buffer).await.expect("read");
                    if read == 0 {
                        break;
                    }
                    assert!(
                        buffer[..read].iter().all(|byte| *byte == 0x5A),
                        "payload corrupted through TLS"
                    );
                    total += read;
                }
                assert_eq!(total, SIZE, "did not receive the whole payload");

                // Then wait for the peer's close_notify before letting this
                // pipe drop. Returning as soon as the payload was counted
                // meant the client could still be sending its close into an
                // end nobody held any more, which is EPIPE: that raced on a
                // fast machine and lost on a two core runner, where it failed
                // the 0.1.1 release. There is no timeout to sit through,
                // because the client sends the close immediately.
                let read = tls.read(&mut buffer).await.expect("read after payload");
                assert_eq!(read, 0, "expected the peer's close, got more data");
            });
        });

        let name = ServerName::try_from("localhost").expect("name");
        let session = ClientConnection::new(client_config, name).expect("session");
        let mut tls = TlsSession::client(client_pipe, session);
        block_on(async move {
            tls.handshake().await.expect("handshake");
            started.recv().expect("server never finished its handshake");
            tls.write_all(&vec![0x5Au8; SIZE]).await.expect("write");
            tls.close().await.expect("close");
        });

        server.join().expect("server thread");
    }

    #[test]
    fn an_untrusted_certificate_is_refused() {
        // The client trusts a certificate generated separately from the one
        // the server presents, so the handshake must fail rather than warn.
        let (server_config, _) = certificate();
        let (_, other_client_config) = certificate();
        let (client_pipe, server_pipe) = pipes();

        let server = std::thread::spawn(move || {
            let session = ServerConnection::new(server_config).expect("session");
            let mut tls = TlsSession::server(server_pipe, session);
            // Fails too, once the client rejects it.
            let _ = block_on(tls.handshake());
        });

        let name = ServerName::try_from("localhost").expect("name");
        let session = ClientConnection::new(other_client_config, name).expect("session");
        let mut tls = TlsSession::client(client_pipe, session);
        assert!(
            block_on(tls.handshake()).is_err(),
            "an unknown certificate was accepted"
        );

        server.join().expect("server thread");
    }
}
