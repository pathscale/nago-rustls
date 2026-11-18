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

    #[cfg(feature = "std")]
    const ECONNRESET_RAW: i32 = libc::ECONNRESET;
    #[cfg(all(not(feature = "std"), feature = "eko"))]
    const ECONNRESET_RAW: i32 = eko::libc_lite::ECONNRESET;
    #[cfg(all(not(feature = "std"), not(feature = "eko")))]
    const ECONNRESET_RAW: i32 = if cfg!(target_vendor = "apple") { 54 } else { 104 };

    #[cfg(feature = "std")]
    const EIO_RAW: i32 = libc::EIO;
    #[cfg(all(not(feature = "std"), feature = "eko"))]
    const EIO_RAW: i32 = eko::libc_lite::EIO;
    #[cfg(all(not(feature = "std"), not(feature = "eko")))]
    const EIO_RAW: i32 = 5;

    #[cfg(feature = "std")]
    const EPROTO_RAW: i32 = libc::EPROTO;
    #[cfg(all(not(feature = "std"), feature = "eko"))]
    const EPROTO_RAW: i32 = eko::libc_lite::EPROTO;
    #[cfg(all(not(feature = "std"), not(feature = "eko")))]
    const EPROTO_RAW: i32 = if cfg!(target_vendor = "apple") { 100 } else { 71 };

    #[cfg(feature = "std")]
    const EPIPE_RAW: i32 = libc::EPIPE;
    #[cfg(all(not(feature = "std"), feature = "eko"))]
    const EPIPE_RAW: i32 = eko::libc_lite::EPIPE;
    #[cfg(all(not(feature = "std"), not(feature = "eko")))]
    const EPIPE_RAW: i32 = 32;

    /// The transport ended during the handshake or before authenticated application-data closure.
    pub const CONNECTION_RESET: Errno = Errno(ECONNRESET_RAW);

    /// rustls reported a state this crate cannot continue from.
    pub const IO: Errno = Errno(EIO_RAW);

    /// A protocol error from the peer: an attack, or a broken implementation.
    /// Either way the session is finished.
    pub const PROTOCOL: Errno = Errno(EPROTO_RAW);

    /// The far end is gone and a write has nowhere to go.
    pub const BROKEN_PIPE: Errno = Errno(EPIPE_RAW);
}
