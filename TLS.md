# Optional native TLS (Dojo fork)

This public fork is based on upstream mummy 0.4.8, commit
`77a7563e87a1045e4e407a3a68731e299fa3507e`. It adds contiguous small WebSocket frames,
batching of queued frames, and optional nonblocking OpenSSL 3 TLS. The upstream MIT license
and history are preserved. The long-lived fork branch is `dojo`; implementation PRs target it.

```nim
import mummy

proc handler(request: Request) =
  request.respond(200, body = "hello")

let server = newServer(handler, tls = TlsConfig(
  certificateFile: "/run/certs/chain.pem",
  privateKeyFile: "/run/certs/key.pem"))
server.serve(Port(8443), "0.0.0.0")
```

Build with Nim 2.2.12 and `--threads:on --mm:orc -d:ssl -d:useOpenssl3 -d:sslVersion=3`.
`sslVersion=3` pins the runtime library, not just the bindings' API. Debian 12 needs `libssl3`.
On macOS install Homebrew OpenSSL 3 and set
`DYLD_LIBRARY_PATH="$(brew --prefix openssl@3)/lib"` when running the executable.
No TLS configuration means ordinary HTTP/WS, even in an SSL-enabled build. Non-SSL builds
remain supported and reject a supplied TLS configuration with `MummyError`.

The configuration requires an unencrypted PEM private key and a PEM certificate chain with
the leaf first. Invalid credentials fail before worker startup. TLS 1.2 is the minimum,
TLS 1.3 is supported, early data and renegotiation are disabled, and HTTP/2 is not advertised.
An Origin CA certificate works for Cloudflare Full (strict); it is not a public browser
certificate. Client certificate authentication and certificate hot reload are not implemented.
Replace certificate files and restart to rotate them.

`handshakeTimeoutMs` defaults to 10,000, `maxPendingHandshakes` to 256, and
`shutdownTimeoutMs` to 1,000. All must be positive. Limits use monotonic deadlines and a heap;
established idle connections are not scanned. On a normal connection close, mummy attempts
to send `close_notify` but does not wait for the peer's reply. Fatal errors close immediately.

TLS objects and all their I/O belong to the selector thread. Each service turn handles at
most 32 KiB of reads and 32 KiB of writes. Buffered decrypted data is scheduled even when
the socket has no fresh readiness notification. A pending write pins its bytes, address and
length; further WebSocket frames batch only into subsequent output buffers. Existing message
limits remain in effect. This does not add an application-level outgoing queue size limit;
applications must still bound how much they enqueue to slow clients.

## Tests

```sh
nim c -r --threads:on --mm:orc tests/test_batching.nim
nim c -r --threads:on --mm:orc tests/test_tls_state.nim
nim c -r --threads:on --mm:orc -d:ssl -d:sslVersion=3 -d:mummyTlsTest tests/test_tls_retry.nim
nim c -d:release --threads:on --mm:orc -d:ssl -d:sslVersion=3 -o:tests/tls_server tests/tls_server.nim
ruby tests/test_tls.rb tests/tls_server
```

The Ruby 4.0.7 standard-library driver verifies real HTTP/HTTPS keep-alive, WS/WSS framing,
buffered records, large frames and backpressure, healthy clients beside a stalled reader,
abrupt resets, TLS 1.2/1.3, handshake deadlines/admission limits, credential errors and shutdown.
The Nim retry test injects deterministic TLS results under `mummyTlsTest`; those hooks are
absent from production builds. CI runs plain and SSL variants on Linux and macOS.

Consumers should pin the full tested Git SHA rather than a moving branch. Updating the fork
means testing its upstream merge and TLS suite first, then updating the consumer's pin and
running its application integration tests. Version `0.5.0` (tag `v0.5.0`) identifies the first
tested TLS revision, while the application pins its full commit SHA.
