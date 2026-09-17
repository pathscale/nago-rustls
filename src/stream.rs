//! The transport this crate sits on.
//!
//! # Why the trait comes from nagoya
//!
//! A TLS session needs somewhere to put ciphertext and somewhere to get it
//! from, and so does every protocol that runs over one. Two crates needing
//! the same trait is exactly the case where restating it costs a bridge: each
//! consumer that uses both would have to write the same mechanical impl to
//! make two identical definitions agree.
//!
//! nagoya is the lower layer and already carries it, so it is taken from
//! there. The other direction does not exist: nagoya cannot depend on a TLS
//! crate.
//!
//! The trait is two methods on purpose. Anything wider would start describing
//! a socket, and then a caller with a Unix socket, an in-memory pipe or
//! another crate's stream would have to pretend to be one.
//!
//! A [`TlsSession`] is itself a [`ByteStream`], so a protocol written against
//! the trait cannot tell whether it is speaking through TLS.
//!
//! [`TlsSession`]: crate::TlsSession

pub use nagoya::io::{Stream as ByteStream, StreamError};
