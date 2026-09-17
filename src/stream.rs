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

use crate::error::Result;

/// Somewhere to read bytes from and write them to.
#[allow(async_fn_in_trait)]
pub trait ByteStream {
    /// Read into `buffer`, returning zero at end of stream.
    async fn read(&mut self, buffer: &mut [u8]) -> Result<usize>;

    /// Write all of `buffer`.
    async fn write_all(&mut self, buffer: &[u8]) -> Result<()>;
}
