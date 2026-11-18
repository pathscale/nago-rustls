//! Drive rustls from any async byte stream, with no runtime attached.
//!
//! # Why this crate exists
//!
//! rustls is already sans-io. Its unbuffered state machine takes ciphertext
//! that arrived, decrypts it, and hands back ciphertext to send. None of it
//! knows what a runtime is.
//!
//! What is usually missing is the loop that drives those calls, and the
//! existing ones are tied to a runtime: `tokio-rustls` needs tokio. This is
//! that loop, written against a two-method trait instead, so it works on a
//! socket from any runtime, on a Unix socket, or on an in-memory pipe in a
//! test with no I/O at all.
//!
//! # What it is not
//!
//! Not a fork of rustls, and not a TLS implementation: all the cryptography
//! and all the protocol is rustls'. This is the plumbing around it, and it is
//! deliberately small enough to read in one sitting.
//!
//! The host supplies a rustls configuration with an explicit crypto provider.
//! This transport enables neither ring nor AWS-LC. Hosts using the optional
//! default-root configuration must install their chosen process provider first.
//!
//! # Example
//!
//! Implement [`ByteStream`] for whatever carries the bytes, then:
//!
//! ```ignore
//! let session = nago_rustls::ClientConnection::new(config, name)?;
//! let mut tls = TlsSession::client(stream, session);
//! tls.handshake().await?;
//! tls.write_all(b"hello").await?;
//! ```
//!
//! A [`TlsSession`] is itself a [`ByteStream`], so a protocol written against
//! that trait cannot tell whether it is speaking through TLS.

#![no_std]
#![deny(missing_docs)]
#![deny(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod error;
mod session;
pub mod stream;

pub use error::{Errno, Result};
pub use session::{ClientConnection, EkoTimeProvider, ServerConnection, TlsSession};
pub use stream::ByteStream;

#[cfg(feature = "webpki-roots")]
pub use session::default_client_config;

// Re-exported so a caller configures TLS without having to match this crate's
// rustls version by hand, which is the usual way a TLS dependency goes wrong.
pub use rustls;
pub use rustls_pki_types;
