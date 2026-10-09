# cl-fips

A pure-Common-Lisp client for FIPS, the Free Internetworking Peering System
([learn.fips.network](https://learn.fips.network); reference implementation
[jmcorgan/fips](https://github.com/jmcorgan/fips), pinned at commit `57bc510`).

It runs as a FIPS node on SBCL on Linux, over UDP (FIPS's default) and TCP, and
interoperates with the upstream node. The protocol code in `src/` is portable
Common Lisp with no FFI, written so that it can also run on modus later. The
socket adapters and the daemon in `transport/` are SBCL-only and marked as such.

**Status: heading for 1.0, not released yet.** It is unpublished. See
[Road to 1.0](#road-to-10) for what is left.

## Running a node

```sh
mkdir -p ~/.cl-fips
scripts/cl-fips-node keygen ~/.cl-fips/fips.key     # prints your npub
scripts/cl-fips-node run ~/.cl-fips/node.conf
```

with `~/.cl-fips/node.conf`:

```lisp
(:identity (:key-file "fips.key")
 :udp (:bind "0.0.0.0:2121")
 :peers ((:npub "npub1..." :transport :udp :addr "198.51.100.7:2121" :alias "relay")))
```

The config is a Lisp property list, read with `*read-eval*` off. Relative paths are
resolved against the config file's directory.

| Key | Meaning |
|---|---|
| `:identity (:key-file F)` | The node's secret: an nsec (or 64 hex digits) on the first line of F, as in upstream's `fips.key`. If F is absent it is created with mode 0600, and F's npub is written to `F.pub`. Without this key, a fresh identity is used each run |
| `:udp (:bind "host:port")` | Listen on UDP (upstream's default is `0.0.0.0:2121`; MTU 1280). Also needed to dial UDP peers |
| `:tcp (:bind "host:port")` | Listen on TCP (MTU 1400) |
| `:peers (...)` | Peers to dial: `:npub`, `:transport` (`:udp` or `:tcp`), `:addr "host:port"`, optional `:alias`. A dropped peer is redialled, backing off from 1 s to 60 s |
| `:echo-ports (N ...)` | Answer DataPackets on these ports with the same bytes (to test reachability) |

From Lisp, load `cl-fips/daemon` and drive it:

```lisp
(let ((d (cl-fips.daemon:make-daemon (cl-fips.daemon:load-config "node.conf")
                                     :on-event (lambda (d ev) (declare (ignore d)) (print ev)))))
  (cl-fips.daemon:daemon-start d)
  (cl-fips.daemon:daemon-send d "npub1..." (map '(vector (unsigned-byte 8)) #'char-code "hi")
                              :dst-port 4600)
  (cl-fips.daemon:daemon-run d))      ; or call DAEMON-STEP from your own loop
```

`DAEMON-SEND` takes an npub. With no session yet, it looks the target up, opens
a session, and sends once the session is up. Data that arrives comes as an
`(:data PEER SRC-PORT DST-PORT BYTES TIMESTAMP)` event. Underneath the daemon,
`fips-node` (`src/node.lisp`) is the same machine without the I/O policy: you hand
it packets and a clock, and it returns events.

## What it does

A Lisp node can:

- link to FIPS nodes over UDP or TCP, in either direction. On a lossy transport
  it resends its handshake, and it notices a peer that has gone silent;
- carry established link frames, with the replay window, rekey and the K-bit
  cutover;
- send MMP reports and read the node's;
- announce its spanning-tree position and a reachability filter, and verify the
  node's announcements;
- complete a Noise XK session (the session layer) with a node, carry
  DataPackets both ways, and rekey that session in both directions;
- send a DataPacket to a node two hops away, through a relay node;
- act as a middle node: forward SessionDatagrams between two peers, so that two
  nodes that are not peers of each other can carry a session through it;
- accept a session another node opens, binding its source address to the key
  its handshake authenticates;
- find a node it knows only by npub (LookupRequest / LookupResponse, with the
  target's signed proof), answer lookups for itself, and pass others on.

All of this is one object, `fips-node` (`src/node.lisp`). The real-node driver
in `test/` is a thin loop around it: it decides which socket has input, and logs
the events the node returns.

Every one of these has been checked against the real upstream `fips` binary,
not only against our own oracle. See [Real-node results](#real-node-results).

## Streams, a gateway, and cl-transport

FIPS carries datagrams. Upstream carries TCP through its IPv6 TUN, which needs
root and a TUN device. `cl-fips/stream` (`transport/fips-stream.lisp`) instead
gives two cl-fips nodes a reliable byte stream: a small windowed, acknowledged
protocol on service port 7100, its own and not upstream's. On top of that it adds
a TCP gateway, and registers `:fips` as a cl-transport backend:

```lisp
(cl-fips.stream:start-fips-client (cl-fips.daemon:load-config "client.conf")
                                  :gateway "npub1...gateway")
(let ((seal.http:*dial* (lambda (h p tm) (cl-transport:dial h p :transport :fips :timeout tm))))
  (seal.http:get-string "https://example.com/"))
```

`scripts/run-seal-over-fips.sh` does exactly that, through a real upstream node
as the relay in the middle: seal → cl-transport → client node → upstream relay →
gateway node → example.com. It fetches `https://example.com/` (577 bytes in about
370 ms) and `https://www.wikipedia.org/` (122 KB in about 670 ms). TLS runs end
to end, so the relay and the gateway see only ciphertext. A gateway opens TCP
connections only for the npubs it is given.

### Any FIPS node's own TCP: `http://<npub>.fips/`

A host named `<npub>.fips` needs no gateway. `:fips` dials it the way upstream's TUN
would carry it: TCP segments from `cl-transport/tcp`, a pure TCP engine, inside
IPv6 shim packets (port 256). Upstream rebuilds them into IPv6 at the far node,
whose own kernel TCP answers. `test/fetch-fips-url.lisp` peers with the public
test mesh (`test-us01.fips.network`) and fetches
`http://npub1crpldvy49ef8z34wlacwujnfudy4nd7k96aqdx5wgn6ckztz7z8q9t59ud.fips/`:
HTTP 200, 141 KB in about 770 ms, with no TUN, no root and no Rust on our side.

### Under a bad network

`scripts/run-conditioned.sh` puts `scripts/netem-proxy.py`, a seeded UDP
impairment proxy, between the nodes. The proxy adds loss, delay, jitter (which
reorders) and duplication, in each direction. Results on this machine, with a
1 MiB random file checked by SHA-256 over the stream, and probes echoed by the
real upstream node:

| profile | stream (1 MiB, byte-exact) | echo probes back (datagrams, no resend) |
|---|---|---|
| clean | 3.8 s | 20 of 20 |
| lossy: 5% loss, 40 ± 20 ms | 5.4 s | 17 of 19 |
| bad: 15% loss, 80 ± 60 ms, 2% duplicated | 11 s | 11 of 19 |
| awful: 30% loss, 150 ± 100 ms, 5% duplicated | 69 s | 7 of 19 |

In every profile, no echo came back altered, and the link never dropped. With
`MESH=1`, the proxy sits in front of `test-us01` on the public mesh, and
`cl-transport/tcp` reads its SSH banner over the IPv6 shim: PASS under clean,
lossy and bad. Two defects were found this way and fixed: the stream's
cumulative-only acks (selective acks now), and a TCP engine that never re-acked
a repeated SYN-ACK.

Not yet: IPv6 for anything but TCP.

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
| `src/lookup.lisp` | Coordinate discovery: LookupRequest / LookupResponse codecs and the signed proof |
| `src/ipv6-shim.lisp` | The IPv6 shim: IPv6 packets in DataPackets on port 256 |
| `src/route.lisp` | Transit forwarding: TTL and path MTU for a SessionDatagram, the next hop from peers' filters, split horizon |
| `src/node.lisp` | The node a program runs: its links, one shared tree, the FSP sessions it opens and accepts, and forwarding. Time is passed in, input is handed to it, and it returns events |
| `src/identity.lisp` | `node_addr` and the FIPS IPv6 address |
| `transport/tcp.lisp` | The TCP adapter (`usocket`, SBCL only) |
| `transport/udp.lisp` | The UDP adapter: one socket, its datagrams sorted into per-peer ports (`usocket`, SBCL only) |
| `transport/fips-stream.lisp` | Byte streams between cl-fips nodes, the TCP gateway, cl-transport's `:fips` (SBCL only) |
| `transport/daemon.lisp` | The runnable node: config, identity file, listeners, dialling and redialling peers, `daemon-send` (SBCL only) |
| `tools/oracle/` | A Rust crate that vendors upstream's Noise and framing code, for interop tests (test tooling only) |
| `scripts/` | The real-node runners |
| `test/` | The test suite and the real-node driver |

## Dependencies

- **natrium** (master, 0af850a or later): SHA-256, HKDF, ChaCha20-Poly1305, the
  CSPRNG, and `natrium.noise` (generic Noise IK and XK with a replay window).
  No curve dependency.
- **secp256k1-fast** (master, ad0705d or later): point arithmetic, the constant-time
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
FIPS_BIN=/path/to/fips ECHO_BIN=/path/to/native-echo SEND_BIN=/path/to/native-send scripts/run-real-node-transit.sh 90
FIPS_BIN=/path/to/fips scripts/run-real-node-udp.sh 40       # the daemon over UDP, both directions
FIPS_BIN=/path/to/fips scripts/run-real-node-lookup.sh 45    # lookups both ways through a relay
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
- **Transit.** Node A to Lisp to node B. Lisp forwards 241 SessionDatagrams,
  B establishes a session from A, and its echo returns A's probe through Lisp.
- **UDP, through the daemon.** The daemon dials the node, and the node dials the
  daemon. In both cases the node promotes the peer and processes our heartbeats
  and ReceiverReports. Its echo returns every probe (19 of 19, then 18 of 18),
  and a flow the node opens reaches us.
- **Lookup.** The daemon is linked only to relay A, and knows B only by its npub.
  It looks B up through A, verifies B's proof, and opens the session with B's
  coordinates; B echoes 22 of 22 probes. In the other direction, node C looks
  the daemon up. We answer, C logs "Discovery succeeded, proof verified", and
  C's datagram reaches us.
- **Two hops.** Lisp to relay A to node B. B establishes the session through A,
  and its echo returns 12 of 12 probes byte for byte.

## Not implemented

- **Upstream's coordinate tie-break in routing.** A transit node forwards by its
  peers' bloom filters only. Upstream also weighs tree distance, and it returns
  error signals to a source it cannot route for. We ignore those signals.
- **Lookup backoff and coordinate-cache expiry.** Looked-up coordinates are
  kept for the life of the node, and a failed lookup is not suppressed before
  it is retried.
- **Link msg1 retransmission on TCP.** On UDP, msg1 is resent at 1, 3, 7 and 15 s.
  TCP is reliable: an unanswered dial is abandoned after 30 s and redialled.
  Our SessionSetup is resent every 4 s, up to 10 times.
- **Session-level MMP** (FSP SenderReport / ReceiverReport, PathMtuNotification).
  We read them and ignore them, and we send none. After a rekey with no data to
  send, we send a CoordsWarmup so the peer sees the new session.
- **Reading the peers' filters** for routing decisions, and parent hysteresis,
  flap dampening and cost-based parent choice.
- **Path-MTU exchange and fragmentation.** A DataPacket larger than about 1290 bytes
  is refused locally.
- **Multi-relay and route-change tests.** The two-hop test has one relay, and the
  transit test has one middle node.
- **IPv6 / TUN.** Applications use the Lisp API, not a network interface.
- **NAT traversal, Nostr discovery, the Tor and BLE transports, and the native
  API socket.**
- **Bare-metal modus.** Hosted modus runs a node (below); bare metal needs a UDP
  port over modus's own NIC stack.
- **Constant-time ECDH off SBCL.** secp256k1-fast's constant-time multiply is
  SBCL-only, so on modus the DH takes secret-dependent time.

## On modus

The daemon runs unchanged inside hosted modus. The UDP adapter is written against
`sb-bsd-sockets` and `sb-sys:wait-until-fd-usable`, which modus provides (sendto,
recvfrom with the sender, and poll were added to its shim for this).
`scripts/run-modus-node.sh` runs a cl-fips node inside `modus --script` against
the real upstream node:

| | link up | echoes |
|---|---|---|
| UDP, modus dials the node | 1.3 s | 18 of 18 |
| UDP, the node dials modus | (at the node's 15 s resend: modus was still loading) | 13 of 13 |
| TCP, modus dials the node | 1.8 s | 18 of 18 |
| TCP, the node dials modus | 11 s | 15 of 15 |

Each time, the node logs our heartbeats, our ReceiverReports and the session.
Both adapters are on `sb-bsd-sockets`, so the same files run on SBCL and modus.
Only the stream/gateway layer (threads, Gray streams) stays SBCL-only. On
modus a Noise IK handshake takes about 3 s, and link frames run at about 120 KB/s.

## Road to 1.0

For SBCL on Linux:

- [x] UDP transport, with handshake resends and dead-link detection
- [x] Coordinate lookup, checked against real nodes in both directions
- [x] A runnable node: config, persistent identity, listeners, redial
- [ ] Repeated real-node runs with recorded pass rates
- [x] A second independent review (FSP, MMP, the transports, lookup, the daemon).
      Its eleven findings are fixed, each with a regression test
      (`test/review-test.lisp`, `test/daemon-test.lisp` D6-D9)
- [x] Merge the `fips-noise` branches of natrium and secp256k1-fast (both on
      master now); the API is documented in `docs/API.md`
- [ ] Tag 1.0

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
