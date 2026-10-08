# fips-oracle

Reference oracle for `cl-fips`.  Emits Noise IK/XK handshake transcripts from
the upstream FIPS Noise module so the Lisp implementation can be checked against
it byte-for-byte.

- `src/noise/` is copied verbatim from `jmcorgan/fips` at commit `57bc510`
  (MIT).  Re-copy and re-verify when upstream moves.
- Only the Noise module is vendored.  The full upstream crate needs libdbus for
  its BLE transport.
- `cargo build --release && ./target/release/oracle ik|xk`
