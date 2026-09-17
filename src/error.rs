//! Errors, which are nagoya's.
//!
//! The code a syscall left behind, rather than a boxed type: the question a
//! caller asks of a failed read is whether it means "not ready yet", which is
//! a comparison rather than a downcast. nagoya's `StreamError` is that, and
//! taking it from there keeps one definition rather than two that have to be
//! converted at every boundary.

pub use nagoya::io::StreamError as Errno;

/// The result of an operation on a stream.
pub type Result<T> = core::result::Result<T, Errno>;

/// The handful of codes this crate reports for itself.
///
/// Spelled out rather than taken from libc, which this crate would otherwise
/// not need at all. All three are the same number on every platform it
/// targets, unlike `EAGAIN`, which is why nagoya spells that one per target
/// and these can sit here.
pub mod codes {
    use super::Errno;

    /// The peer hung up mid handshake.
    pub const CONNECTION_RESET: Errno = Errno(54);

    /// rustls reported a state this crate cannot continue from.
    pub const IO: Errno = Errno(5);

    /// A protocol error from the peer: an attack, or a broken implementation.
    /// Either way the session is finished.
    pub const PROTOCOL: Errno = Errno(100);

    /// The far end is gone and a write has nowhere to go.
    pub const BROKEN_PIPE: Errno = Errno(32);
}
