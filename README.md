# cl-fips

A pure-Common-Lisp client for FIPS, the Free Internetworking Peering System
([learn.fips.network](https://learn.fips.network); reference implementation
[jmcorgan/fips](https://github.com/jmcorgan/fips), pinned at commit `57bc510`).

The point is to run as a peer on modus, which has no FFI, no Linux and no Rust.
Development and tests run on SBCL. The protocol code in `src/` makes no
SBCL-specific calls. The socket adapter in `transport/` is SBCL-only and marked
as such.

**Status: a development snapshot, not a release.** It is unpublished, and the
protocol is not complete (see [Not implemented](#not-implemented)).

## What it does

A Lisp node can:

- complete a Noise IK handshake (the link layer) with a FIPS node over TCP,
  in either direction;
- carry established link frames, with the replay window, rekey and the K-bit
  cutover;
- send MMP reports and read the node's;
- announce its spanning-tree position and a reachability filter, and verify the
  node's announcements;
- complete a Noise XK session (the session layer) with a node, carry
  DataPackets both ways, and rekey that session in both directions;
- send a DataPacket to a node two hops away, through a relay node.

Every one of these has been checked against the real upstream `fips` binary,
not only against our own oracle. See [Real-node results](#real-node-results).

## Layout

| Path | What |
|---|---|
| `src/wire.lisp` | Little-endian codecs, the FMP common prefix, the stream framing rule, the FMP and FSP headers |
| `src/fips-noise.lisp` | The FIPS suite (secp256k1 keys, the FIPS ECDH, the 0x02 pre-message) bound to `natrium.noise` |
| `src/fmp.lisp` | Established link frames: seal and open, with the replay check |
| `src/link.lisp` | The link state machine over a byte port: IK, frames, rekey, MMP, opt-in routing |
| `src/rekey.lisp` | The link rekey state machine: time and counts passed in, nothing read from a clock |
| `src/mmp.lisp` | SenderReport and ReceiverReport codecs, and the counting they need |
| `src/stp.lisp` | TreeAnnounce: codec, signing, verification, the semantic checks |
| `src/bloom.lisp` | The reachability filter and the FilterAnnounce codec |
| `src/tree.lisp` | Our spanning-tree declaration, from the peers' verified announces |
| `src/fsp.lisp` | The end-to-end session: SessionDatagram, the XK handshake bodies, DataPacket frames, rekey, drain |
| `src/identity.lisp` | `node_addr` and the FIPS IPv6 address |
| `transport/tcp.lisp` | The TCP adapter (`usocket`, SBCL only) |
| `tools/oracle/` | A Rust crate that vendors upstream's Noise and framing code, for interop tests (test tooling only) |
| `scripts/` | The real-node runners |
| `test/` | The test suite and the real-node driver |

## Dependencies

- **natrium** (branch `fips-noise`): SHA-256, HKDF, ChaCha20-Poly1305, the
  CSPRNG, and `natrium.noise` (generic Noise IK and XK with a replay window).
  No curve dependency.
- **secp256k1-fast** (branch `fips-noise`): point arithmetic, the constant-time
  variable-base multiply used by the DH, and the FIPS ECDH and SEC1 codec.
  No dependencies.
- **usocket**: the TCP adapter only. The protocol code does not use it.
- **cargo** (Rust), for the oracle. Only the tests need it.

`run-tests.sh` looks for the two pure-CL dependencies at `$NATRIUM_DIR` and
`$SECP256K1_DIR`, defaulting to `~/natrium` and `~/secp256k1-fast`.

## Running the tests

```sh
./run-tests.sh                 # the whole suite, with the upstream oracle
CL_FIPS_NO_ORACLE=1 ./run-tests.sh   # without the oracle; the interop arms skip
```

The oracle builds on first use (`cargo build --release` in `tools/oracle/`).
The suite ends with `N checks, 0 failures` and exits non-zero on any failure.

### Against a real node

Build the upstream binary from `jmcorgan/fips` at `57bc510` (it needs
`libdbus-1` for the BLE transport, even though the TCP path does not use it),
then:

```sh
FIPS_BIN=/path/to/fips scripts/run-real-node.sh 150
FIPS_BIN=/path/to/fips ECHO_BIN=/path/to/native-echo scripts/run-real-node-multihop.sh 60
```

`native-echo` is upstream's `examples/native-echo`, built beside the binary. It
holds a port on the node, and the probes go to it. Without `FIPS_BIN` the scripts
print `SKIPPED` and exit 0.

The 150-second run is needed for the rekey checks. The link rekeys near 105–135 s,
and our FSP rekey starts at 60 s by default.

Environment knobs, for the real-node runs:

| Variable | Default | Effect |
|---|---|---|
| `CL_FIPS_REPORTS` | `all` | `no-rr` drops our ReceiverReports (the negative control); `off` sends none |
| `CL_FIPS_ROUTING` | on | `off` sends no TreeAnnounce or FilterAnnounce |
| `CL_FIPS_FSP` | on | `off` runs no end-to-end session |
| `CL_FIPS_ECHO` | on | `off` probes the IPv6 shim (port 256) instead of the echo (port 4600) |
| `CL_FIPS_PROBE_BYTES` | 15 | The probe size. The limit is 1290 bytes at a 1400-byte MTU |
| `CL_FIPS_FSP_REKEY_AT` | 60 | Seconds before we start an FSP rekey; `off` never does |
| `CL_FIPS_FSP_PEER_DIR` | unset | A directory whose `node.key` names a node behind the linked one (multi-hop) |
| `CL_FIPS_NODE_SEND` | on | `off` skips the node-initiated datagram |

## Real-node results

Upstream `fips` built from `57bc510`, run on loopback (the node's own log is what
these come from):

- **Link.** The IK handshake completes in both directions. Heartbeats are
  accepted. Link rekeys complete, cut over, and frames continue. MMP reports are
  accepted (about 145 per run). The node does not resend its announcements, and
  it never removes the peer. A run of 170 seconds was clean.
- **Routing.** The node processes our TreeAnnounce and treats us as a tree peer.
  It records our FilterAnnounce.
- **End-to-end session.** The node establishes the XK session as responder, and
  decrypts and dispatches our DataPackets. Its native-echo returns our probes byte
  for byte: 30 of 30 in a 150-second run, at 15 bytes and at 1000 bytes. A 1290-byte
  probe passes, and 1291 bytes is refused locally.
- **Node-initiated data.** A local client on the node opens a flow to our npub,
  and the datagram reaches us, byte for byte.
- **Rekey, both directions.** The node rekeys our FSP session and we answer; we
  rekey its session and it completes. The node logs the cutover in both cases.
- **Two hops.** Lisp to relay A to node B. B establishes the session through A,
  and its echo returns 12 of 12 probes byte for byte.

## Not implemented

- **Transit forwarding.** We are an endpoint. We do not forward SessionDatagrams
  for other peers.
- **Our own coordinate caching.** We send `[destination]` as the destination's
  coordinates when we have no better path. We do not learn the real ancestry.
- **Retransmission** of our link msg1 (the node does retransmit its own).
  Our SessionSetup is resent every 4 s, up to 10 times.
- **Reading the peers' filters** for routing decisions, and parent hysteresis,
  flap dampening and cost-based parent choice.
- **Path-MTU exchange and fragmentation.** A DataPacket larger than about 1290 bytes
  is refused locally.
- **Multi-relay and route-change tests.** The two-hop test has one relay.
- **Running on modus.** The protocol code is written to be portable, but nothing
  has been run on modus. The tests use `sb-ext`, and the transport uses `usocket`.

## Interop and the oracle

`tools/oracle/` holds upstream's Noise module and framing code, vendored
verbatim from `jmcorgan/fips @ 57bc510` (MIT). Its interactive modes
(`verify-ik-*`, `verify-xk-*`, `verify-frame`, `verify-rekey`, `serve-tcp`,
`dial-tcp`, `dial-raw`, `node-addr`) let the Lisp code be checked against
upstream in both directions. The oracle is test tooling. Nothing in `src/` calls
Rust.

Not everything in the oracle is verbatim. The Noise module and the frame and
framing wire code are copied from upstream. Two parts are transcribed by hand:
`verify-rekey` runs a copy of upstream's peer-state and frame-receive logic, and
`read_fmp_packet` was rewritten for blocking I/O. The commit messages say which.
The real-node runs are the stronger check, since they run the node's own code.

## Licence

MIT, as the upstream code it vendors.
