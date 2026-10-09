#!/bin/sh
# run-real-node-multihop.sh -- cl-fips to a node TWO HOPS away, through a real
# upstream `fips` relay.
#
#   FIPS_BIN=/path/to/fips ECHO_BIN=/path/to/native-echo scripts/run-real-node-multihop.sh [SECS]
#
# Topology: Lisp --TCP--> node A (relay) <--TCP-- node B (echo).  Lisp is a direct
# peer of A only.  Its FSP session is with B: the SessionDatagrams are forwarded by
# A, and B answers from its native-echo on port 4600.  Passes when the session is
# established at B (responder, XK), A forwards traffic, and the echo returns our
# probes byte for byte.  Without FIPS_BIN this prints SKIPPED and exits 0.
set -u
SECS=${1:-60}
if [ -z "${FIPS_BIN:-}" ] || [ ! -x "${FIPS_BIN:-}" ]; then
  echo "SKIPPED: set FIPS_BIN to an upstream fips binary (jmcorgan/fips @ 57bc510)"
  exit 0
fi
HERE=$(cd "$(dirname "$0")/.." && pwd)
DIR=$(mktemp -d /tmp/cl-fips-multihop.XXXXXX)
LISP="sbcl --script $HERE/test/real-node-test.lisp"
ECHO_BIN="${ECHO_BIN:-$(dirname "$FIPS_BIN")/examples/native-echo}"
free_port() { python3 -I -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
fail=0

$LISP keygen "$DIR" || { echo "FAIL: keygen A"; exit 1; }
mkdir -p "$DIR/b" && $LISP keygen "$DIR/b" || { echo "FAIL: keygen B"; exit 1; }
PA=$(free_port); PB=$(free_port)

# node A: the relay.  No peers configured: it accepts B and Lisp inbound.
cat > "$DIR/a.yaml" <<YAML
node:
  identity:
    nsec: "$(head -1 "$DIR/node.key")"
  log_level: trace
  control:
    socket_path: "$DIR/ca.sock"
tun:
  enabled: false
dns:
  enabled: false
transports:
  tcp:
    bind_addr: "127.0.0.1:$PA"
YAML

# node B: the echo.  It dials A as a static peer, and serves the native API.
cat > "$DIR/b.yaml" <<YAML
node:
  identity:
    nsec: "$(head -1 "$DIR/b/node.key")"
  log_level: trace
  control:
    socket_path: "$DIR/cb.sock"
  native_api:
    enabled: true
    socket_path: "$DIR/bapi.sock"
tun:
  enabled: false
dns:
  enabled: false
transports:
  tcp:
    bind_addr: "127.0.0.1:$PB"
peers:
  - npub: "$(cat "$DIR/node.npub")"
    alias: "node-a"
    addresses:
      - transport: tcp
        addr: "127.0.0.1:$PA"
YAML

"$FIPS_BIN" -c "$DIR/a.yaml" > "$DIR/node-a.log" 2>&1 &
PAID=$!
i=0; until grep -q "TCP accept loop starting" "$DIR/node-a.log" || [ $i -ge 50 ]; do sleep 0.2; i=$((i+1)); done
"$FIPS_BIN" -c "$DIR/b.yaml" > "$DIR/node-b.log" 2>&1 &
PBID=$!
i=0; until [ -S "$DIR/bapi.sock" ] || [ $i -ge 50 ]; do sleep 0.2; i=$((i+1)); done
EP=""
if [ -x "$ECHO_BIN" ]; then
  "$ECHO_BIN" "$DIR/bapi.sock" 4600 > "$DIR/echo-b.log" 2>&1 &
  EP=$!
  i=0; until grep -q "accepting on port" "$DIR/echo-b.log" 2>/dev/null || [ $i -ge 50 ]; do sleep 0.2; i=$((i+1)); done
else
  echo "  (native-echo not built at $ECHO_BIN)"; fail=1
fi
# give B time to dial A and the tree to settle before the session starts
sleep 5

echo "== Lisp -> A -> B (${SECS}s)"
CL_FIPS_FSP_PEER_DIR="$DIR/b" CL_FIPS_NODE_SEND=off timeout $((SECS + 60)) \
  $LISP dial "$DIR" "$PA" "$SECS" > "$DIR/lisp.log" 2>&1 || fail=1
sleep 1
kill $EP $PBID $PAID 2>/dev/null; wait 2>/dev/null

grep -E "HANDSHAKE|PASS|FAIL" "$DIR/lisp.log" | sed 's/^/  /'
ok=$(grep -c "FSP echo OK" "$DIR/lisp.log"); bad=$(grep -c "FSP echo MISMATCH" "$DIR/lisp.log")
est=$(grep -c "Session established (responder, XK)" "$DIR/node-b.log")
srv=$(grep -c "Native API flow closed by its client local=4600" "$DIR/node-b.log")
if [ "$est" -ge 1 ]; then echo "  B: FSP session established (responder, XK), reached through A"
else echo "  FAIL: B never established the FSP session"; fail=1; fi
if [ "$srv" -ge 1 ]; then echo "  B: native-echo served $srv DataPackets from Lisp on port 4600"
else echo "  FAIL: B served no DataPacket from Lisp"; fail=1; fi
if [ "$bad" -ge 1 ]; then echo "  FAIL: $bad echo replies did not match"; fail=1
elif [ "$ok" -ge 1 ]; then echo "  echo: B returned $ok of our probes through A, byte for byte"
else echo "  FAIL: no echo reply through A from B"; fail=1; fi
fwd=$(grep -ci "forward" "$DIR/node-a.log")
echo "  A: $fwd forwarding log lines"
if [ "$fail" -eq 0 ]; then echo "MULTIHOP: PASS"; else echo "MULTIHOP: FAIL"; fi
echo "logs: $DIR"
exit "$fail"
