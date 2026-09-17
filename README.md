# nago-rustls

Drive [rustls](https://github.com/rustls/rustls) from any async byte stream,
with no runtime attached.

No OpenSSL and no C: rustls with the `ring` provider is the whole backend,
which is what the name is for.

## Why

rustls is already sans-io. `read_tls` takes ciphertext that arrived,
`process_new_packets` decrypts it, `write_tls` hands back ciphertext to send.
None of it knows what a runtime is.

What is usually missing is the loop that drives those calls, and the existing
ones are tied to a runtime: `tokio-rustls` needs tokio. This is that loop,
written against a two-method trait instead:

```rust
pub trait ByteStream {
    async fn read(&mut self, buffer: &mut [u8]) -> Result<usize>;
    async fn write_all(&mut self, buffer: &[u8]) -> Result<()>;
}
```

So it works on a socket from any runtime, on a Unix socket, or on an in-memory
pipe in a test with no I/O at all. The tests do exactly that: a full handshake
and a 200 KiB payload over a channel pair, no sockets involved.

A `TlsSession` is itself a `ByteStream`, so a protocol written against the
trait cannot tell whether it is speaking through TLS.

## What it is not

Not a fork of rustls and not a TLS implementation. All the cryptography and
all the protocol is rustls'; this is the plumbing around it, small enough to
read in one sitting.

## Status

Early. It was extracted from [nago-wss](https://github.com/pathscale/nago-wss)
once it turned out to have nothing to do with WebSockets, and it has run
against one transport on one platform. The Linux path compiles but has not
been exercised.
