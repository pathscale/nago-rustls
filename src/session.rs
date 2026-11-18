//! The TLS loop: rustls driven over a byte stream.
//!
//! # Why there is no fork of rustls here
//!
//! rustls is already sans-io. Its unbuffered state machine takes ciphertext
//! that arrived, decrypts it, and hands back ciphertext to send. None of it
//! knows what a runtime is, so what is needed on top is a loop rather than a
//! rewrite, and this module is that loop.
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

/// The TLS client connection type.
pub use rustls::client::UnbufferedClientConnection as ClientConnection;
/// The TLS server connection type.
pub use rustls::server::UnbufferedServerConnection as ServerConnection;

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
    /// Ciphertext received from the transport that has not yet been consumed by
    /// the unbuffered rustls state machine.
    tls_incoming: Vec<u8>,
    /// Ciphertext encoded by the unbuffered rustls state machine waiting to be
    /// flushed to the transport.
    tls_outgoing: Vec<u8>,
    /// Plaintext rustls has decrypted but the caller has not taken yet.
    incoming: Vec<u8>,
    /// Where in `incoming` the caller has read up to.
    taken: usize,
    /// The rustls error that ended the session, kept for the caller to report.
    error: Option<rustls::Error>,
    peer_closed: bool,
}

/// Which side of the handshake this is.
enum Session {
    Client(alloc::boxed::Box<ClientConnection>),
    Server(alloc::boxed::Box<ServerConnection>),
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Client(_) => f.write_str("Session::Client(..)"),
            Self::Server(_) => f.write_str("Session::Server(..)"),
        }
    }
}

impl<S: ByteStream> TlsSession<S> {
    /// Start a client session over an already connected stream.
    pub fn client(stream: S, session: ClientConnection) -> Self {
        Self {
            stream,
            session: Session::Client(alloc::boxed::Box::new(session)),
            tls_incoming: Vec::new(),
            tls_outgoing: Vec::new(),
            incoming: Vec::new(),
            taken: 0,
            error: None,
            peer_closed: false,
        }
    }

    /// Start a server session over an already accepted stream.
    pub fn server(stream: S, session: ServerConnection) -> Self {
        Self {
            stream,
            session: Session::Server(alloc::boxed::Box::new(session)),
            tls_incoming: Vec::new(),
            tls_outgoing: Vec::new(),
            incoming: Vec::new(),
            taken: 0,
            error: None,
            peer_closed: false,
        }
    }

    /// The rustls error behind the last PROTOCOL failure, if there was one.
    ///
    /// The errno says the session is finished; this says why, for example
    /// which certificate a verifier refused.
    pub fn tls_error(&self) -> Option<&rustls::Error> {
        self.error.as_ref()
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

    /// Take a client session apart after the handshake, for a caller that
    /// drives rustls through its own poll-based loop, such as an HTTP/2
    /// codec. Returns the stream, the rustls connection and any plaintext
    /// already decrypted but not yet read. A server session is returned
    /// unchanged.
    pub fn into_client_parts(
        self,
    ) -> core::result::Result<(S, alloc::boxed::Box<ClientConnection>, Vec<u8>), Self> {
        match self.session {
            Session::Client(session) => {
                let mut incoming = self.incoming;
                incoming.drain(..self.taken);
                Ok((self.stream, session, incoming))
            }
            session => Err(Self { session, ..self }),
        }
    }
}

enum StepOutcome {
    Encoded,
    Transmit,
    BlockedHandshake,
    WriteReady,
    Closed,
}

fn encode_with_resize<Data>(
    mut encode_data: rustls::unbuffered::EncodeTlsData<'_, Data>,
    tls_outgoing: &mut Vec<u8>,
) -> Result<()> {
    let start = tls_outgoing.len();
    tls_outgoing.resize(start + 16 * 1024, 0);
    match encode_data.encode(&mut tls_outgoing[start..]) {
        Ok(written) => {
            tls_outgoing.truncate(start + written);
            Ok(())
        }
        Err(rustls::unbuffered::EncodeError::InsufficientSize(ise)) => {
            tls_outgoing.resize(start + ise.required_size, 0);
            match encode_data.encode(&mut tls_outgoing[start..]) {
                Ok(written) => {
                    tls_outgoing.truncate(start + written);
                    Ok(())
                }
                Err(_) => {
                    tls_outgoing.truncate(start);
                    Err(codes::IO)
                }
            }
        }
        Err(_) => {
            tls_outgoing.truncate(start);
            Err(codes::IO)
        }
    }
}

fn encrypt_with_resize<Data>(
    mut write_traffic: rustls::unbuffered::WriteTraffic<'_, Data>,
    plaintext: &[u8],
    tls_outgoing: &mut Vec<u8>,
) -> Result<()> {
    let start = tls_outgoing.len();
    let guess = plaintext.len().saturating_add(2048);
    tls_outgoing.resize(start + guess, 0);
    match write_traffic.encrypt(plaintext, &mut tls_outgoing[start..]) {
        Ok(written) => {
            tls_outgoing.truncate(start + written);
            Ok(())
        }
        Err(rustls::unbuffered::EncryptError::InsufficientSize(ise)) => {
            tls_outgoing.resize(start + ise.required_size, 0);
            match write_traffic.encrypt(plaintext, &mut tls_outgoing[start..]) {
                Ok(written) => {
                    tls_outgoing.truncate(start + written);
                    Ok(())
                }
                Err(_) => {
                    tls_outgoing.truncate(start);
                    Err(codes::IO)
                }
            }
        }
        Err(_) => {
            tls_outgoing.truncate(start);
            Err(codes::IO)
        }
    }
}

fn close_with_resize<Data>(
    mut write_traffic: rustls::unbuffered::WriteTraffic<'_, Data>,
    tls_outgoing: &mut Vec<u8>,
) -> Result<()> {
    let start = tls_outgoing.len();
    tls_outgoing.resize(start + 256, 0);
    match write_traffic.queue_close_notify(&mut tls_outgoing[start..]) {
        Ok(written) => {
            tls_outgoing.truncate(start + written);
            Ok(())
        }
        Err(rustls::unbuffered::EncryptError::InsufficientSize(ise)) => {
            tls_outgoing.resize(start + ise.required_size, 0);
            match write_traffic.queue_close_notify(&mut tls_outgoing[start..]) {
                Ok(written) => {
                    tls_outgoing.truncate(start + written);
                    Ok(())
                }
                Err(_) => {
                    tls_outgoing.truncate(start);
                    Err(codes::IO)
                }
            }
        }
        Err(_) => {
            tls_outgoing.truncate(start);
            Err(codes::IO)
        }
    }
}

fn step_unbuffered<Data>(
    status: rustls::unbuffered::UnbufferedStatus<'_, '_, Data>,
    incoming: &mut Vec<u8>,
    tls_outgoing: &mut Vec<u8>,
    peer_closed: &mut bool,
) -> core::result::Result<(usize, StepOutcome), (usize, rustls::Error)> {
    use rustls::unbuffered::ConnectionState;

    let mut discard = status.discard;
    match status.state {
        Ok(ConnectionState::ReadTraffic(mut traffic)) => {
            while let Some(record) = traffic.next_record() {
                match record {
                    Ok(app_data) => {
                        discard += app_data.discard;
                        incoming.extend_from_slice(app_data.payload);
                    }
                    Err(err) => return Err((discard, err)),
                }
            }
            Ok((discard, StepOutcome::Encoded))
        }
        Ok(ConnectionState::EncodeTlsData(encode_data)) => {
            if encode_with_resize(encode_data, tls_outgoing).is_err() {
                return Err((discard, rustls::Error::General("encode failed".into())));
            }
            Ok((discard, StepOutcome::Encoded))
        }
        Ok(ConnectionState::TransmitTlsData(transmit)) => {
            transmit.done();
            Ok((discard, StepOutcome::Transmit))
        }
        Ok(ConnectionState::BlockedHandshake) => Ok((discard, StepOutcome::BlockedHandshake)),
        Ok(ConnectionState::WriteTraffic(_)) => Ok((discard, StepOutcome::WriteReady)),
        Ok(ConnectionState::PeerClosed) => {
            *peer_closed = true;
            Ok((discard, StepOutcome::Encoded))
        }
        Ok(ConnectionState::Closed) => {
            *peer_closed = true;
            Ok((discard, StepOutcome::Closed))
        }
        Ok(_) => Ok((discard, StepOutcome::BlockedHandshake)),
        Err(err) => Err((discard, err)),
    }
}

impl<S: ByteStream> TlsSession<S> {
    fn is_handshaking(&self) -> bool {
        match &self.session {
            Session::Client(session) => session.is_handshaking(),
            Session::Server(session) => session.is_handshaking(),
        }
    }

    async fn flush_tls_outgoing(&mut self) -> Result<bool> {
        if self.tls_outgoing.is_empty() {
            return Ok(false);
        }
        self.stream.write_all(&self.tls_outgoing).await?;
        self.tls_outgoing.clear();
        Ok(true)
    }

    async fn drive_records(&mut self) -> Result<(bool, StepOutcome)> {
        let mut sent = self.flush_tls_outgoing().await?;
        loop {
            let outcome = match &mut self.session {
                Session::Client(session) => {
                    let status = session.process_tls_records(&mut self.tls_incoming);
                    step_unbuffered(
                        status,
                        &mut self.incoming,
                        &mut self.tls_outgoing,
                        &mut self.peer_closed,
                    )
                }
                Session::Server(session) => {
                    let status = session.process_tls_records(&mut self.tls_incoming);
                    if let Ok(rustls::unbuffered::ConnectionState::ReadEarlyData(mut traffic)) =
                        status.state
                    {
                        let mut discard = status.discard;
                        let mut early_err = None;
                        while let Some(record) = traffic.next_record() {
                            match record {
                                Ok(app_data) => {
                                    discard += app_data.discard;
                                    self.incoming.extend_from_slice(app_data.payload);
                                }
                                Err(err) => {
                                    early_err = Some(err);
                                    break;
                                }
                            }
                        }
                        match early_err {
                            Some(err) => Err((discard, err)),
                            None => Ok((discard, StepOutcome::Encoded)),
                        }
                    } else {
                        step_unbuffered(
                            status,
                            &mut self.incoming,
                            &mut self.tls_outgoing,
                            &mut self.peer_closed,
                        )
                    }
                }
            };

            match outcome {
                Ok((discard, step)) => {
                    if discard > 0 {
                        self.tls_incoming.drain(..discard);
                    }
                    match step {
                        StepOutcome::Encoded => continue,
                        StepOutcome::Transmit => {
                            sent |= self.flush_tls_outgoing().await?;
                            continue;
                        }
                        other => {
                            sent |= self.flush_tls_outgoing().await?;
                            return Ok((sent, other));
                        }
                    }
                }
                Err((discard, err)) => {
                    if discard > 0 {
                        self.tls_incoming.drain(..discard);
                    }
                    self.error = Some(err);
                    // Drain any alert queued by rustls before reporting failure.
                    loop {
                        let alert_step = match &mut self.session {
                            Session::Client(session) => {
                                let status = session.process_tls_records(&mut self.tls_incoming);
                                step_unbuffered(
                                    status,
                                    &mut self.incoming,
                                    &mut self.tls_outgoing,
                                    &mut self.peer_closed,
                                )
                            }
                            Session::Server(session) => {
                                let status = session.process_tls_records(&mut self.tls_incoming);
                                step_unbuffered(
                                    status,
                                    &mut self.incoming,
                                    &mut self.tls_outgoing,
                                    &mut self.peer_closed,
                                )
                            }
                        };
                        match alert_step {
                            Ok((alert_discard, StepOutcome::Encoded)) => {
                                if alert_discard > 0 {
                                    self.tls_incoming.drain(..alert_discard);
                                }
                                continue;
                            }
                            Ok((alert_discard, StepOutcome::Transmit)) => {
                                if alert_discard > 0 {
                                    self.tls_incoming.drain(..alert_discard);
                                }
                                let _ = self.flush_tls_outgoing().await;
                                break;
                            }
                            Err((alert_discard, _)) => {
                                if alert_discard > 0 {
                                    self.tls_incoming.drain(..alert_discard);
                                }
                                break;
                            }
                            _ => break,
                        }
                    }
                    let _ = self.flush_tls_outgoing().await;
                    return Err(codes::PROTOCOL);
                }
            }
        }
    }

    async fn read_transport(&mut self) -> Result<usize> {
        let mut chunk = [0u8; 16 * 1024];
        let read = self.stream.read(&mut chunk).await?;
        if read == 0 {
            return if self.peer_closed {
                Ok(0)
            } else {
                Err(codes::CONNECTION_RESET)
            };
        }
        self.tls_incoming.extend_from_slice(&chunk[..read]);
        Ok(read)
    }

    /// Run the handshake to completion.
    pub async fn handshake(&mut self) -> Result<()> {
        while self.is_handshaking() {
            let (wrote, _) = self.drive_records().await?;
            if !self.is_handshaking() {
                break;
            }
            if !wrote && self.read_transport().await? == 0 {
                return Err(codes::CONNECTION_RESET);
            }
        }
        let _ = self.drive_records().await?;
        Ok(())
    }

    /// Read decrypted bytes into `buffer`.
    pub async fn read(&mut self, buffer: &mut [u8]) -> Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            if self.taken < self.incoming.len() {
                let available = self.incoming.len() - self.taken;
                let take = available.min(buffer.len());
                buffer[..take].copy_from_slice(&self.incoming[self.taken..self.taken + take]);
                self.taken += take;

                if self.taken == self.incoming.len() {
                    self.incoming.clear();
                    self.taken = 0;
                }
                return Ok(take);
            }

            if self.peer_closed {
                return Ok(0);
            }

            let _ = self.drive_records().await?;
            if self.taken < self.incoming.len() || self.peer_closed {
                continue;
            }

            if self.read_transport().await? == 0 {
                return Ok(0);
            }
        }
    }

    /// Write plaintext, encrypting and sending all of it.
    pub async fn write_all(&mut self, buffer: &[u8]) -> Result<()> {
        if buffer.is_empty() {
            return Ok(());
        }
        self.handshake().await?;
        let _ = self.drive_records().await?;

        let encrypt_res = match &mut self.session {
            Session::Client(session) => {
                let status = session.process_tls_records(&mut self.tls_incoming);
                let discard = status.discard;
                let res = match status.state {
                    Ok(rustls::unbuffered::ConnectionState::WriteTraffic(write_traffic)) => {
                        encrypt_with_resize(write_traffic, buffer, &mut self.tls_outgoing)
                    }
                    Ok(rustls::unbuffered::ConnectionState::TransmitTlsData(mut transmit)) => {
                        if let Some(write_traffic) = transmit.may_encrypt_app_data() {
                            let res =
                                encrypt_with_resize(write_traffic, buffer, &mut self.tls_outgoing);
                            transmit.done();
                            res
                        } else {
                            transmit.done();
                            Err(codes::IO)
                        }
                    }
                    _ => Err(codes::IO),
                };
                if discard > 0 {
                    self.tls_incoming.drain(..discard);
                }
                res
            }
            Session::Server(session) => {
                let status = session.process_tls_records(&mut self.tls_incoming);
                let discard = status.discard;
                let res = match status.state {
                    Ok(rustls::unbuffered::ConnectionState::WriteTraffic(write_traffic)) => {
                        encrypt_with_resize(write_traffic, buffer, &mut self.tls_outgoing)
                    }
                    Ok(rustls::unbuffered::ConnectionState::TransmitTlsData(mut transmit)) => {
                        if let Some(write_traffic) = transmit.may_encrypt_app_data() {
                            let res =
                                encrypt_with_resize(write_traffic, buffer, &mut self.tls_outgoing);
                            transmit.done();
                            res
                        } else {
                            transmit.done();
                            Err(codes::IO)
                        }
                    }
                    _ => Err(codes::IO),
                };
                if discard > 0 {
                    self.tls_incoming.drain(..discard);
                }
                res
            }
        };
        encrypt_res?;
        self.flush_tls_outgoing().await?;
        Ok(())
    }

    /// Send a close_notify and stop.
    pub async fn close(&mut self) -> Result<()> {
        let _ = self.drive_records().await?;
        let close_res = match &mut self.session {
            Session::Client(session) => {
                let status = session.process_tls_records(&mut self.tls_incoming);
                let discard = status.discard;
                let res = match status.state {
                    Ok(rustls::unbuffered::ConnectionState::WriteTraffic(write_traffic)) => {
                        close_with_resize(write_traffic, &mut self.tls_outgoing)
                    }
                    _ => Ok(()),
                };
                if discard > 0 {
                    self.tls_incoming.drain(..discard);
                }
                res
            }
            Session::Server(session) => {
                let status = session.process_tls_records(&mut self.tls_incoming);
                let discard = status.discard;
                let res = match status.state {
                    Ok(rustls::unbuffered::ConnectionState::WriteTraffic(write_traffic)) => {
                        close_with_resize(write_traffic, &mut self.tls_outgoing)
                    }
                    _ => Ok(()),
                };
                if discard > 0 {
                    self.tls_incoming.drain(..discard);
                }
                res
            }
        };
        close_res?;
        let _ = self.drive_records().await?;
        self.flush_tls_outgoing().await?;
        Ok(())
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

/// Time provider backed by `eko::time::epoch_secs()`.
#[derive(Debug, Clone, Copy, Default)]
pub struct EkoTimeProvider;

impl rustls::time_provider::TimeProvider for EkoTimeProvider {
    fn current_time(&self) -> Option<rustls_pki_types::UnixTime> {
        let secs = eko::time::epoch_secs();
        if secs >= 0 {
            Some(rustls_pki_types::UnixTime::since_unix_epoch(
                core::time::Duration::from_secs(secs as u64),
            ))
        } else {
            None
        }
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
    let provider = rustls::crypto::CryptoProvider::get_default()
        .expect("no process-default rustls CryptoProvider installed")
        .clone();
    alloc::sync::Arc::new(
        rustls::ClientConfig::builder_with_details(
            provider,
            alloc::sync::Arc::new(EkoTimeProvider),
        )
        .with_safe_default_protocol_versions()
        .expect("default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::codes;
    use alloc::string::ToString;
    use alloc::sync::Arc;
    use alloc::vec;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc::{Receiver, SyncSender};
    use std::sync::Arc as StdArc;

    const PHASE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

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

        // The host picks the provider; these tests pick the ECC-only one.
        let provider = Arc::new(ps_rustcrypto::provider());
        let time_provider = Arc::new(EkoTimeProvider);
        let server =
            rustls::ServerConfig::builder_with_details(provider.clone(), time_provider.clone())
                .with_safe_default_protocol_versions()
                .expect("versions")
                .with_no_client_auth()
                .with_single_cert(vec![certificate.clone()], key)
                .expect("server config");

        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).expect("trust the test certificate");
        let client = rustls::ClientConfig::builder_with_details(provider, time_provider)
            .with_safe_default_protocol_versions()
            .expect("versions")
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
        reads: StdArc<AtomicUsize>,
        writes: StdArc<AtomicUsize>,
    }

    impl ByteStream for Pipe {
        async fn read(&mut self, buffer: &mut [u8]) -> Result<usize> {
            self.reads.fetch_add(1, Ordering::SeqCst);
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
                    // A real disconnect is transport EOF. A stalled fixture
                    // is an I/O failure, so it cannot masquerade as closure.
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return Ok(0),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => return Err(codes::IO),
                }
            }
            let take = self.pending.len().min(buffer.len());
            buffer[..take].copy_from_slice(&self.pending[..take]);
            self.pending.drain(..take);
            Ok(take)
        }

        async fn write_all(&mut self, buffer: &[u8]) -> Result<()> {
            self.writes.fetch_add(1, Ordering::SeqCst);
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
                reads: StdArc::new(AtomicUsize::new(0)),
                writes: StdArc::new(AtomicUsize::new(0)),
            },
            Pipe {
                outgoing: to_client,
                incoming: server_receives,
                pending: Vec::new(),
                reads: StdArc::new(AtomicUsize::new(0)),
                writes: StdArc::new(AtomicUsize::new(0)),
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
    fn a_large_reply_read_in_small_pieces_arrives_whole() {
        // Server to client, many records in one write, read through a small
        // buffer: the client must drain rustls between batches, or read_tls
        // fails with "received plaintext buffer full" past 16 KiB.
        const SIZE: usize = 96 * 1024;
        let (server_config, client_config) = certificate();
        let (client_pipe, server_pipe) = pipes();

        let server = std::thread::spawn(move || {
            let session = ServerConnection::new(server_config).expect("session");
            let mut tls = TlsSession::server(server_pipe, session);
            block_on(async move {
                tls.handshake().await.expect("handshake");
                let mut buffer = [0u8; 4];
                let read = tls.read(&mut buffer).await.expect("read");
                assert_eq!(&buffer[..read], b"send");
                let payload: Vec<u8> = (0..SIZE).map(|index| (index % 251) as u8).collect();
                tls.write_all(&payload).await.expect("write");
                tls.close().await.expect("close");
            });
        });

        let name = ServerName::try_from("localhost").expect("name");
        let session = ClientConnection::new(client_config, name).expect("session");
        let mut tls = TlsSession::client(client_pipe, session);
        let received = block_on(async move {
            tls.handshake().await.expect("handshake");
            tls.write_all(b"send").await.expect("write");
            let mut received = Vec::new();
            let mut buffer = [0u8; 1000];
            loop {
                let read = tls.read(&mut buffer).await.expect("read");
                if read == 0 {
                    break;
                }
                received.extend_from_slice(&buffer[..read]);
            }
            received
        });
        server.join().expect("server thread");

        assert_eq!(received.len(), SIZE, "did not receive the whole reply");
        assert!(
            received
                .iter()
                .enumerate()
                .all(|(index, byte)| *byte == (index % 251) as u8),
            "reply corrupted through TLS"
        );
    }

    #[test]
    fn closure_truncated_transport_returns_reset_after_plaintext() {
        const PAYLOAD: &[u8] = b"truncated";
        let (server_config, client_config) = certificate();
        let (client_pipe, server_pipe) = pipes();
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);

        let server = std::thread::spawn(move || {
            let session = ServerConnection::new(server_config).expect("session");
            let mut tls = TlsSession::server(server_pipe, session);
            block_on(async move {
                tls.handshake().await.expect("handshake");
                ready_tx.try_send(()).expect("signal handshake completion");
                let mut buffer = [0u8; 3];
                let mut received = Vec::new();
                while received.len() < PAYLOAD.len() {
                    let read = ByteStream::read(&mut tls, &mut buffer)
                        .await
                        .expect("payload read");
                    assert_ne!(read, 0, "transport closed before the payload arrived");
                    received.extend_from_slice(&buffer[..read]);
                }
                assert_eq!(received, PAYLOAD, "plaintext bytes or order changed");
                assert_eq!(
                    ByteStream::read(&mut tls, &mut buffer).await,
                    Err(codes::CONNECTION_RESET),
                    "transport EOF without close_notify must reset after plaintext"
                );
            });
        });

        let name = ServerName::try_from("localhost").expect("name");
        let session = ClientConnection::new(client_config, name).expect("session");
        let mut tls = TlsSession::client(client_pipe, session);
        block_on(async move {
            tls.handshake().await.expect("handshake");
            ready_rx
                .recv_timeout(PHASE_TIMEOUT)
                .expect("server never finished its handshake");
            tls.write_all(PAYLOAD).await.expect("write payload");
            // Dropping the session drops its sending pipe without close_notify.
            drop(tls);
        });

        server.join().expect("server thread");
    }

    #[test]
    fn closure_close_notify_drains_plaintext_then_repeats_eof() {
        const PAYLOAD: &[u8] = b"close-notify-payload";
        let (server_config, client_config) = certificate();
        let (client_pipe, server_pipe) = pipes();
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);

        let server = std::thread::spawn(move || {
            let session = ServerConnection::new(server_config).expect("session");
            let mut tls = TlsSession::server(server_pipe, session);
            block_on(async move {
                tls.handshake().await.expect("handshake");
                ready_tx.try_send(()).expect("signal handshake completion");
                let mut short = [0u8; 2];
                let transport_reads = tls.get_ref().reads.load(Ordering::SeqCst);
                let read = ByteStream::read(&mut tls, &mut short)
                    .await
                    .expect("first read");
                assert_eq!(&short[..read], &PAYLOAD[..2]);
                assert_eq!(
                    tls.get_ref().reads.load(Ordering::SeqCst),
                    transport_reads + 1
                );
                assert!(
                    tls.peer_closed,
                    "the first transport read must include close_notify"
                );
                assert!(
                    tls.incoming.len() > tls.taken,
                    "plaintext remainder should be buffered"
                );

                let cursor = tls.taken;
                let reads = tls.get_ref().reads.load(Ordering::SeqCst);
                let writes = tls.get_ref().writes.load(Ordering::SeqCst);
                let mut empty = [];
                assert_eq!(
                    ByteStream::read(&mut tls, &mut empty)
                        .await
                        .expect("empty read"),
                    0
                );
                assert_eq!(
                    tls.taken, cursor,
                    "empty read advanced the plaintext cursor"
                );
                assert_eq!(tls.get_ref().reads.load(Ordering::SeqCst), reads);
                assert_eq!(tls.get_ref().writes.load(Ordering::SeqCst), writes);

                let mut remainder = [0u8; 32];
                let read = ByteStream::read(&mut tls, &mut remainder)
                    .await
                    .expect("remainder");
                assert_eq!(&remainder[..read], &PAYLOAD[2..]);
                assert_eq!(
                    tls.incoming.len(),
                    tls.taken,
                    "buffered plaintext was not drained"
                );

                let reads = tls.get_ref().reads.load(Ordering::SeqCst);
                let writes = tls.get_ref().writes.load(Ordering::SeqCst);
                let mut nonempty = [0u8; 1];
                assert_eq!(
                    ByteStream::read(&mut tls, &mut nonempty)
                        .await
                        .expect("first EOF"),
                    0
                );
                assert_eq!(
                    ByteStream::read(&mut tls, &mut nonempty)
                        .await
                        .expect("repeated EOF"),
                    0
                );
                assert_eq!(
                    tls.get_ref().reads.load(Ordering::SeqCst),
                    reads,
                    "clean EOF touched transport reads"
                );
                assert_eq!(
                    tls.get_ref().writes.load(Ordering::SeqCst),
                    writes,
                    "clean EOF touched transport writes"
                );
            });
        });

        let name = ServerName::try_from("localhost").expect("name");
        let session = ClientConnection::new(client_config, name).expect("session");
        let mut tls = TlsSession::client(client_pipe, session);
        block_on(async move {
            tls.handshake().await.expect("handshake");
            ready_rx
                .recv_timeout(PHASE_TIMEOUT)
                .expect("server never finished its handshake");
            let _ = tls.drive_records().await.expect("drive records");
            match &mut tls.session {
                Session::Client(session) => {
                    let status = session.process_tls_records(&mut tls.tls_incoming);
                    let discard = status.discard;
                    match status.state {
                        Ok(rustls::unbuffered::ConnectionState::WriteTraffic(write_traffic)) => {
                            encrypt_with_resize(write_traffic, PAYLOAD, &mut tls.tls_outgoing)
                                .expect("queue plaintext");
                            let status2 = session.process_tls_records(&mut []);
                            if let Ok(rustls::unbuffered::ConnectionState::WriteTraffic(wt)) =
                                status2.state
                            {
                                close_with_resize(wt, &mut tls.tls_outgoing)
                                    .expect("queue close_notify");
                            } else {
                                panic!("expected WriteTraffic after encrypt");
                            }
                        }
                        _ => panic!("expected WriteTraffic"),
                    }
                    if discard > 0 {
                        tls.tls_incoming.drain(..discard);
                    }
                }
                Session::Server(_) => unreachable!(),
            }
            // One flush sends queued application data followed by close_notify.
            tls.flush_tls_outgoing().await.expect("flush");
        });

        server.join().expect("server thread");
    }

    #[test]
    fn closure_empty_read_preserves_buffer_and_skips_io() {
        const PAYLOAD: &[u8] = b"buffered";
        let (server_config, client_config) = certificate();
        let (client_pipe, server_pipe) = pipes();
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let (send_payload_tx, send_payload_rx) = std::sync::mpsc::sync_channel(1);
        let (finished_tx, finished_rx) = std::sync::mpsc::sync_channel(1);

        let server = std::thread::spawn(move || {
            let session = ServerConnection::new(server_config).expect("session");
            let mut tls = TlsSession::server(server_pipe, session);
            block_on(async move {
                tls.handshake().await.expect("handshake");
                ready_tx.try_send(()).expect("signal handshake completion");
                send_payload_rx
                    .recv_timeout(PHASE_TIMEOUT)
                    .expect("client did not request payload");
                tls.write_all(PAYLOAD).await.expect("write payload");
                finished_rx
                    .recv_timeout(PHASE_TIMEOUT)
                    .expect("client did not finish");
            });
        });

        let name = ServerName::try_from("localhost").expect("name");
        let session = ClientConnection::new(client_config, name).expect("session");
        let mut tls = TlsSession::client(client_pipe, session);
        block_on(async move {
            tls.handshake().await.expect("handshake");
            ready_rx
                .recv_timeout(PHASE_TIMEOUT)
                .expect("server never finished its handshake");

            let reads = tls.get_ref().reads.load(Ordering::SeqCst);
            let writes = tls.get_ref().writes.load(Ordering::SeqCst);
            let mut empty = [];
            assert_eq!(
                ByteStream::read(&mut tls, &mut empty)
                    .await
                    .expect("open empty read"),
                0
            );
            assert_eq!(tls.get_ref().reads.load(Ordering::SeqCst), reads);
            assert_eq!(tls.get_ref().writes.load(Ordering::SeqCst), writes);

            send_payload_tx
                .try_send(())
                .expect("signal server to send payload");
            let mut short = [0u8; 3];
            let read = ByteStream::read(&mut tls, &mut short)
                .await
                .expect("short read");
            assert_eq!(&short[..read], &PAYLOAD[..3]);
            assert!(
                tls.incoming.len() > tls.taken,
                "short read should leave plaintext buffered"
            );
            let cursor = tls.taken;
            let reads = tls.get_ref().reads.load(Ordering::SeqCst);
            let writes = tls.get_ref().writes.load(Ordering::SeqCst);
            assert_eq!(
                ByteStream::read(&mut tls, &mut empty)
                    .await
                    .expect("buffered empty read"),
                0
            );
            assert_eq!(
                tls.taken, cursor,
                "empty read advanced the plaintext cursor"
            );
            assert_eq!(tls.get_ref().reads.load(Ordering::SeqCst), reads);
            assert_eq!(tls.get_ref().writes.load(Ordering::SeqCst), writes);

            let mut remainder = [0u8; 8];
            let read = ByteStream::read(&mut tls, &mut remainder)
                .await
                .expect("buffered remainder");
            assert_eq!(&remainder[..read], &PAYLOAD[3..]);
            finished_tx.try_send(()).expect("signal completion");
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
            // Fails too, once the client rejects it, and hears why.
            let _ = block_on(tls.handshake());
            tls.tls_error().cloned()
        });

        let name = ServerName::try_from("localhost").expect("name");
        let session = ClientConnection::new(other_client_config, name).expect("session");
        let mut tls = TlsSession::client(client_pipe, session);
        assert!(
            block_on(tls.handshake()).is_err(),
            "an unknown certificate was accepted"
        );
        // Same subject, different key: the chain fails its signature check.
        let Some(rustls::Error::InvalidCertificate(refused)) = tls.tls_error().cloned() else {
            panic!("no certificate error kept: {:?}", tls.tls_error());
        };

        // The alert reached the server rather than dying in the buffer.
        assert_eq!(
            server.join().expect("server thread"),
            Some(rustls::Error::AlertReceived(refused.into()))
        );
    }
}
