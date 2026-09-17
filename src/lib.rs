//! Drive rustls from any async byte stream, with no runtime attached.
//!
//! # Why this crate exists
//!
//! rustls is already sans-io. [`read_tls`] takes ciphertext that arrived,
//! [`process_new_packets`] decrypts it, and [`write_tls`] hands back
//! ciphertext to send. None of it knows what a runtime is.
//!
//! What is usually missing is the loop that drives those calls, and the
//! existing ones are tied to a runtime: `tokio-rustls` needs tokio. This is
//! that loop, written against a two-method trait instead, so it works on a
//! socket from any runtime, on a Unix socket, or on an in-memory pipe in a
//! test with no I/O at all.
//!
//! [`read_tls`]: rustls::ConnectionCommon::read_tls
//! [`write_tls`]: rustls::ConnectionCommon::write_tls
//! [`process_new_packets`]: rustls::ConnectionCommon::process_new_packets
//!
//! # What it is not
//!
//! Not a fork of rustls, and not a TLS implementation: all the cryptography
//! and all the protocol is rustls'. This is the plumbing around it, and it is
//! deliberately small enough to read in one sitting.
//!
//! There is no OpenSSL here and no C at all. rustls with the `ring` provider
//! is the whole backend, which is the point of naming the crate after it.
//!
//! # Example
//!
//! Implement [`ByteStream`] for whatever carries the bytes, then:
//!
//! ```ignore
//! let session = rustls::ClientConnection::new(config, name)?;
//! let mut tls = TlsSession::client(stream, session);
//! tls.handshake().await?;
//! tls.write_all(b"hello").await?;
//! ```
//!
//! A [`TlsSession`] is itself a [`ByteStream`], so a protocol written against
//! that trait cannot tell whether it is speaking through TLS.

#![deny(missing_docs)]
// Denied rather than forbidden so that exactly one module can opt out and say
// why: reading this thread's errno is a dereference of a pointer libc hands
// out, and there is no safe binding for it. The TLS loop itself, which is the
// part worth auditing, is unsafe-free and says so.
#![deny(unsafe_code)]

extern crate alloc;

pub mod error;
mod session;
pub mod stream;

pub use error::{Errno, Result};
pub use session::TlsSession;
pub use stream::ByteStream;

#[cfg(feature = "webpki-roots")]
pub use session::default_client_config;

// Re-exported so a caller configures TLS without having to match this crate's
// rustls version by hand, which is the usual way a TLS dependency goes wrong.
pub use rustls;
pub use rustls_pki_types;
