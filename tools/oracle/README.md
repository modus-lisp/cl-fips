# fips-oracle

Reference oracle for `cl-fips`.  Emits Noise IK/XK handshake transcripts from
the upstream FIPS Noise module so the Lisp implementation can be checked against
it byte-for-byte.

- `src/noise/` is copied verbatim from `jmcorgan/fips` at commit `57bc510`
  (MIT).  Re-copy and re-verify when upstream moves.
- Only the Noise module is vendored.  The full upstream crate needs libdbus for
  its BLE transport.
- `cargo build --release && ./target/release/oracle ik|xk`
- `src/fmp_wire.rs` copies parts of upstream `src/proto/fmp/wire.rs` verbatim
  (line ranges in its header), including the msg1/msg2 packets a link rekey
  travels in.
- Interactive modes (documented at the top of `src/bin/oracle.rs`):
  `verify-ik-*`, `verify-xk-*`, `verify-frame`, `node-addr`,
  `verify-xk-responder-retry[-plain]` (a corrupted msg3 delivery followed by
  the genuine one) and `verify-rekey` (one side of an FMP link rekey; its rekey
  driver transliterates upstream's `peer/active.rs` and
  `node/dataplane/encrypted.rs`, which are not vendored).
- TCP modes `serve-tcp`, `dial-tcp` (IK + FMP frames over real loopback TCP)
  and `dial-raw` (a raw peer for malformed input) read packets with
  `src/framing.rs`: upstream `src/transport/framing.rs`, constants and
  `StreamError` verbatim, `read_fmp_packet` transliterated from tokio to
  blocking `std::io::Read`.
