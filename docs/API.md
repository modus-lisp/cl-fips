# cl-fips API

Three levels, from the one most programs want to the protocol parts underneath.
Only the first two are the stable 1.0 API; the third is exported for tests,
tools and other transports, and may change.

## 1. The daemon — `cl-fips.daemon` (system `cl-fips/daemon`, SBCL)

A running node: sockets, a clock, dialling and redialling.

| Function | |
|---|---|
| `(load-config path)` | Read a config plist (see the README); `*read-eval*` is off. |
| `(make-daemon config &key keypair on-event log)` | A daemon. `on-event` is called as `(funcall on-event daemon event)` for every event; `log` is a stream for one line per event, or NIL. `keypair` overrides the config's identity. |
| `(daemon-start d)` | Open the listeners. Returns `d`. |
| `(daemon-step d &key (max-wait-ms 200))` | One turn: start due dials, wait for input up to `max-wait-ms`, handle all of it, tick. |
| `(daemon-run d &key until max-wait-ms)` | Step until `daemon-stop` is called or `(funcall until)` is true. |
| `(daemon-stop d)` | Close every link, dial and listener. |
| `(daemon-send d peer data &key src-port dst-port)` | Send `data` (octets) to `peer`: an npub, a 33-byte key, or the 16-byte address of a node that has a session with us. Returns `:sent`, or `:queued` while a session is opened (by lookup if needed). Signals `cl-fips:node-error` (`:too-big`, `:queue-full`, `:no-session`). |
| `(daemon-peer-up-p d peer)` | True when the session with `peer` is established. |
| `(daemon-npub d)`, `(daemon-node d)`, `(daemon-udp-port d)`, `(daemon-tcp-port d)` | Accessors. |
| `(load-or-create-identity path)` | `(values keypair created-p)`; writes an nsec file (0600) and `path.pub` if absent. |
| `(write-identity path keypair)` | Write a key file and its `.pub`. |
| `(format-event event)` | One line describing an event. |
| `(main args)` | The command line behind `scripts/cl-fips-node`. |

The daemon adds its own events to the node's: `(:started npub udp-port tcp-port)`,
`(:peer-up who transport)`, `(:peer-down who reason)`,
`(:dial-failed who reason)`, `(:accept-failed who reason)`, `(:send-failed addr message)`.

## 2. The node — `cl-fips` (system `cl-fips`, portable)

The protocol with no I/O policy: you give it links, packets and the time in
milliseconds; it returns events (lists, the first element naming them; the full
list is at the top of `src/node.lisp`). Nothing reads a clock or a socket.

| Function | |
|---|---|
| `(make-fips-node keypair)` | A node. `fips-node-tree` is the tree its links must share. |
| `(node-add-link node link)`, `(node-remove-link node link)` | Links come from `stream-link-initiate`, `stream-link-accept` or `link-dial-receive`, made with `:routing (fips-node-tree node)`. |
| `(node-receive node link &key timeout-ms now)` | Read one packet from `link` and act on it. Returns events. |
| `(node-tick node now)` | Heartbeats, rekeys, reports, announces, resends, lookups, dead-link reaping. Returns events. |
| `(node-open-session node peer-key &key peer-coords via now)` | Open an end-to-end session; `(values session :sent|:queued)`. |
| `(node-send-data node peer-addr data &key src-port dst-port now)` | Send on an established session. |
| `(node-lookup node peer-key &key now)` | Find a node's coordinates; answered by `(:lookup-ok addr coords path-mtu)` or `(:lookup-failed addr)`. |
| `(node-start-rekey node peer-addr &key now)` | Rekey a session now (the node also rekeys on its own schedule). |
| `(node-session node addr)`, `(node-route node addr)`, `(node-cached-coords node addr)`, `(node-our-coords node)`, `(node-peer-coords node addr)`, `(node-tree-peer-p node addr)` | Queries. |
| `node-error`, `node-error-reason` | The condition the node signals. |

Links and ports (`src/link.lisp`):

| Function | |
|---|---|
| `(make-byte-port read-exactly write-all &optional close)` | A stream transport, as three closures. |
| `(make-datagram-port read-packet write-all &optional close)` | A datagram transport. |
| `(stream-link-initiate port keypair peer-key epoch &key mtu timeout-ms routing ...)` | Dial and wait for the answer. |
| `(stream-link-dial ...)`, `(link-dial-receive dial)`, `(link-dial-tick dial now)`, `(link-dial-next-due-ms dial)` | The same, without waiting. |
| `(stream-link-accept port keypair epoch &key mtu timeout-ms routing ...)` | Answer a dial. |
| `link-error`, `link-error-reason`, `link-error-fatal-p` | A fatal one has closed the port. |

Identity (`src/identity.lisp`, `src/fips-noise.lisp`):
`generate-keypair`, `node-addr`, `fips-address`, `fips-address-string`,
`npub-encode`, `npub-decode`, `nsec-encode`, `nsec-decode`, `bech32-encode`,
`bech32-decode`.

## 3. Protocol parts

Exported so the tests and other adapters can reach them; not a stable API.
Wire codecs (`wire.lisp`), FMP frames (`fmp.lisp`), the link rekey machine
(`rekey.lisp`), MMP reports (`mmp.lisp`), TreeAnnounce and the tree
(`stp.lisp`, `tree.lisp`), the bloom filter (`bloom.lisp`), FSP sessions
(`fsp.lisp`), transit forwarding (`route.lisp`), lookup messages
(`lookup.lisp`). Each file's header names the upstream source it follows.

## Transports — `cl-fips.transport` (system `cl-fips/transport`, SBCL)

`tcp-connect`, `tcp-listen`, `tcp-accept`, `tcp-listener-port`,
`tcp-listener-close`, `socket-byte-port`; `udp-open`, `udp-close`,
`udp-peer-port`, `udp-accept`, `udp-pump`, `udp-port-ready-p`,
`udp-accept-pending-p`, `udp-endpoint-local-port`. A port for another
platform needs only the closures of `make-byte-port` or `make-datagram-port`.
