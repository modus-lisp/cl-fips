#!/bin/sh
# run-real-node-transit.sh -- Lisp as a TRANSIT node between two real upstream nodes.
#
#   FIPS_BIN=/path/to/fips ECHO_BIN=/path/to/native-echo SEND_BIN=/path/to/native-send \
#     scripts/run-real-node-transit.sh [SECS]
#
# Topology: A (originator, native API) --TCP--> Lisp (middle) <--TCP-- B (echo).
# B's key is chosen to have the smallest node_addr, so B is the root of the tree.
# Lisp forwards SessionDatagrams between its two links.  A then opens a native flow
# to B's npub on port 4600; the session runs A -> Lisp -> B, and B's echo returns the
# bytes the same way.  Passes when Lisp forwarded datagrams, B established the
# session (responder, XK), and the echo returned our probe.  Without FIPS_BIN, SKIPPED.
set -u
SECS=${1:-90}
if [ -z "${FIPS_BIN:-}" ] || [ ! -x "${FIPS_BIN:-}" ]; then
  echo "SKIPPED: set FIPS_BIN to an upstream fips binary (jmcorgan/fips @ 57bc510)"
  exit 0
fi
HERE=$(cd "$(dirname "$0")/.." && pwd)
DIR=$(mktemp -d /tmp/cl-fips-transit.XXXXXX)
LISP="sbcl --script $HERE/test/real-node-test.lisp"
ECHO_BIN="${ECHO_BIN:-$(dirname "$FIPS_BIN")/examples/native-echo}"
SEND_BIN="${SEND_BIN:-$(dirname "$FIPS_BIN")/examples/native-send}"
free_port() { python3 -I -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
fail=0

$LISP keygen-root "$DIR" || { echo "FAIL: keygen-root"; exit 1; }
PA=$(free_port); PL=$(free_port); PB=$(free_port)

cat > "$DIR/a.yaml" <<YAML
node:
  identity:
    nsec: "$(head -1 "$DIR/node.key")"
  log_level: trace
  control:
    socket_path: "$DIR/ca.sock"
  native_api:
    enabled: true
    socket_path: "$DIR/aapi.sock"
tun:
  enabled: false
dns:
  enabled: false
transports:
  tcp:
    bind_addr: "127.0.0.1:$PA"
YAML

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
  - npub: "$(cat "$DIR/lisp.npub")"
    alias: "lisp"
    addresses:
      - transport: tcp
        addr: "127.0.0.1:$PL"
YAML

"$FIPS_BIN" -c "$DIR/a.yaml" > "$DIR/node-a.log" 2>&1 &
PAID=$!
i=0; until grep -q "TCP accept loop starting" "$DIR/node-a.log" || [ $i -ge 50 ]; do sleep 0.2; i=$((i+1)); done

# Lisp: dials A, then listens for B
$LISP transit "$DIR" "$PA" "$PL" "$SECS" > "$DIR/lisp-transit.log" 2>&1 &
LPID=$!
i=0; until grep -q "LISTENING" "$DIR/lisp-transit.log" 2>/dev/null || [ $i -ge 150 ]; do sleep 0.2; i=$((i+1)); done

"$FIPS_BIN" -c "$DIR/b.yaml" > "$DIR/node-b.log" 2>&1 &
PBID=$!
i=0; until [ -S "$DIR/bapi.sock" ] || [ $i -ge 50 ]; do sleep 0.2; i=$((i+1)); done
EP=""
if [ -x "$ECHO_BIN" ]; then
  "$ECHO_BIN" "$DIR/bapi.sock" 4600 > "$DIR/echo-b.log" 2>&1 &
  EP=$!
  i=0; until grep -q "accepting on port" "$DIR/echo-b.log" 2>/dev/null || [ $i -ge 50 ]; do sleep 0.2; i=$((i+1)); done
fi

# let the tree settle and the SessionSetup warm A's cache, then A opens a flow to B
sleep 25
if [ -x "$SEND_BIN" ]; then
  "$SEND_BIN" "$DIR/aapi.sock" "$(cat "$DIR/b/node.npub")" 4600 "transit-probe" > "$DIR/send.log" 2>&1
  cat "$DIR/send.log" | sed 's/^/  A: /'
else
  echo "  (native-send not built at $SEND_BIN)"; fail=1
fi

wait $LPID 2>/dev/null; lrc=$?
sleep 3
kill $EP $PBID $PAID 2>/dev/null; wait 2>/dev/null

grep -E "HANDSHAKE|TRANSIT|SessionSetup|established through|FAIL" "$DIR/lisp-transit.log" | sed 's/^/  Lisp: /' | head -12
fwd=$(grep -o "forwarded=[0-9]*" "$DIR/lisp-transit.log" | tail -1 | cut -d= -f2)
est=$(grep -c "Session established (responder, XK)" "$DIR/node-b.log")
ech=$(grep -c "returned" "$DIR/echo-b.log" 2>/dev/null)
echo "  B: FSP sessions established as responder: $est"
echo "  B: echo replies: $ech"
if [ "${fwd:-0}" -ge 1 ]; then echo "  Lisp: forwarded $fwd SessionDatagrams between A and B"
else echo "  FAIL: Lisp forwarded no datagrams"; fail=1; fi
if [ "$est" -ge 1 ]; then :; else echo "  FAIL: B never established the session"; fail=1; fi
if [ "$ech" -ge 1 ]; then echo "  echo: B returned our probe through the middle"
else echo "  FAIL: no echo reply"; fail=1; fi
[ "$lrc" -eq 0 ] || { echo "  FAIL: the Lisp transit node exited $lrc"; fail=1; }
if [ "$fail" -eq 0 ]; then echo "TRANSIT: PASS"; else echo "TRANSIT: FAIL"; fi
echo "logs: $DIR"
exit "$fail"
