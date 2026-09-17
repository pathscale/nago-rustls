//! The transport this crate sits on.
//!
//! # Why the trait is this small
//!
//! A TLS session needs somewhere to put ciphertext and somewhere to get it
//! from. That is the whole of it, so that is the whole of the trait. Anything
//! wider would start describing a socket, and then a caller with a Unix
//! socket, an in-memory pipe or another crate's stream would have to pretend
//! to be one.
//!
//! It is also what makes the result composable: a [`TlsSession`] is itself a
//! [`ByteStream`], so a protocol written against this trait cannot tell
//! whether it is speaking through TLS.
//!
//! [`TlsSession`]: crate::TlsSession
//!
//! # Why not nagoya's `io::Stream`
//!
//! nagoya 0.1.3 has the same two methods, and taking them from there would
//! spare a consumer that uses both crates the bridge between two identical
//! definitions. It would also pull a work-stealing scheduler, its queues and
//! the futures machinery around them, thirteen crates, into a TLS crate that
//! runs none of it.
//!
//! That is the `tokio-rustls` mistake at smaller scale: a glue crate carrying
//! a runtime because that is where the trait happened to live. A consumer with
//! both writes a few lines of bridge instead, which is the cheaper of the two.

use crate::error::Result;

/// Somewhere to read bytes from and write them to.
#[allow(async_fn_in_trait)]
pub trait ByteStream {
    /// Read into `buffer`, returning zero at end of stream.
    async fn read(&mut self, buffer: &mut [u8]) -> Result<usize>;

    /// Write all of `buffer`.
    async fn write_all(&mut self, buffer: &[u8]) -> Result<()>;
}
