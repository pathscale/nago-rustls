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
/// These use the target's native errno values, matching the lower-level
/// stream error convention.
pub mod codes {
    use super::Errno;

    /// The transport ended during the handshake or before authenticated application-data closure.
    pub const CONNECTION_RESET: Errno = Errno(libc::ECONNRESET);

    /// rustls reported a state this crate cannot continue from.
    pub const IO: Errno = Errno(5);

    /// A protocol error from the peer: an attack, or a broken implementation.
    /// Either way the session is finished.
    pub const PROTOCOL: Errno = Errno(libc::EPROTO);

    /// The far end is gone and a write has nowhere to go.
    pub const BROKEN_PIPE: Errno = Errno(32);
}
