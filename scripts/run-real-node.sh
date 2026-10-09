#!/bin/sh
# run-real-node.sh -- cl-fips against a REAL upstream `fips` node over TCP.
#
#   FIPS_BIN=/path/to/fips scripts/run-real-node.sh [SECS]
#
# FIPS_BIN is the daemon built from jmcorgan/fips @ 57bc510 (`cargo build
# --release`; the bluer dependency needs libdbus-1 headers, e.g. a local build of
# dbus 1.14 on PKG_CONFIG_PATH).  Without FIPS_BIN this prints SKIPPED and exits 0.
#
# Two arms, each with a fresh node and fresh keys (test/real-node-test.lisp):
#   dial    the node listens on 127.0.0.1:<ephemeral>; Lisp dials it (IK initiator)
#   accept  Lisp listens on 127.0.0.1:<ephemeral>; the node dials it as a static
#           peer (Lisp is the IK responder)
# Each arm passes when the Lisp side completes the handshake and receives a
# TreeAnnounce and a Heartbeat, AND the node's own log says the peer was
# promoted to active and that it received our heartbeats.  Everything binds
# loopback; the node has TUN and DNS off and its control socket in the temp dir.
set -u
SECS=${1:-20}
if [ -z "${FIPS_BIN:-}" ] || [ ! -x "${FIPS_BIN:-}" ]; then
  echo "SKIPPED: set FIPS_BIN to an upstream fips binary (jmcorgan/fips @ 57bc510)"
  exit 0
fi
HERE=$(cd "$(dirname "$0")/.." && pwd)
DIR=$(mktemp -d /tmp/cl-fips-real-node.XXXXXX)
LISP="sbcl --script $HERE/test/real-node-test.lisp"
free_port() { python3 -I -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
fail=0

node_yaml() {  # $1 file, $2 tcp port, $3 optional peer port
  {
    echo "node:"
    echo "  identity:"
    echo "    nsec: \"$(head -1 "$DIR/node.key")\""
    echo "  log_level: trace"
    echo "  control:"
    echo "    socket_path: \"$DIR/control.sock\""
    echo "tun:"
    echo "  enabled: false"
    echo "dns:"
    echo "  enabled: false"
    echo "transports:"
    echo "  tcp:"
    echo "    bind_addr: \"127.0.0.1:$2\""
    if [ -n "${3:-}" ]; then
      echo "peers:"
      echo "  - npub: \"$(cat "$DIR/lisp.npub")\""
      echo "    alias: \"cl-fips\""
      echo "    addresses:"
      echo "      - transport: tcp"
      echo "        addr: \"127.0.0.1:$3\""
    fi
  } > "$1"
}

check_node_log() {  # $1 arm, $2 log
  addr=$(cat "$DIR/node.addr")
  if grep -q "node_addr: $addr" "$2"; then echo "  node_addr matches cl-fips node-addr ($addr)"
  else echo "  FAIL: node_addr in the log is not $addr"; fail=1; fi
  if grep -q "Connection promoted to active peer" "$2"; then echo "  node: peer promoted to active"
  else echo "  FAIL: node never promoted the peer"; fail=1; fi
  hb=$(grep -c "Received heartbeat" "$2")
  if [ "$hb" -ge 1 ]; then echo "  node: received $hb heartbeats from Lisp"
  else echo "  FAIL: node logged no heartbeat from Lisp"; fail=1; fi
}

$LISP keygen "$DIR" || { echo "FAIL: keygen"; exit 1; }

# --- dial: Lisp initiator -> node -------------------------------------------------
P=$(free_port)
node_yaml "$DIR/dial.yaml" "$P"
"$FIPS_BIN" -c "$DIR/dial.yaml" > "$DIR/node-dial.log" 2>&1 &
NP=$!
i=0; until grep -q "TCP accept loop starting" "$DIR/node-dial.log" || [ $i -ge 50 ]; do sleep 0.2; i=$((i+1)); done
echo "== dial (node on 127.0.0.1:$P)"
timeout $((SECS + 60)) $LISP dial "$DIR" "$P" "$SECS" > "$DIR/lisp-dial.log" 2>&1 || fail=1
sleep 1; kill $NP 2>/dev/null; wait $NP 2>/dev/null
grep -E "HANDSHAKE|msg_types|remote static|PASS|FAIL" "$DIR/lisp-dial.log" | sed 's/^/  /'
check_node_log dial "$DIR/node-dial.log"

# --- accept: node initiator -> Lisp ------------------------------------------------
P=$(free_port); LP=$(free_port)
node_yaml "$DIR/accept.yaml" "$P" "$LP"
timeout $((SECS + 120)) $LISP accept "$DIR" "$LP" "$SECS" > "$DIR/lisp-accept.log" 2>&1 &
AP=$!
i=0; until grep -q LISTENING "$DIR/lisp-accept.log" || [ $i -ge 300 ]; do sleep 0.2; i=$((i+1)); done
echo "== accept (Lisp on 127.0.0.1:$LP)"
"$FIPS_BIN" -c "$DIR/accept.yaml" > "$DIR/node-accept.log" 2>&1 &
NP=$!
wait $AP || fail=1
kill $NP 2>/dev/null; wait $NP 2>/dev/null
grep -E "HANDSHAKE|msg_types|remote static|PASS|FAIL" "$DIR/lisp-accept.log" | sed 's/^/  /'
check_node_log accept "$DIR/node-accept.log"

if ss -ltn 2>/dev/null | grep -q -E "127.0.0.1:($P|$LP) "; then echo "FAIL: a port is still listening"; fail=1; fi
echo "logs: $DIR"
[ $fail -eq 0 ] && echo "REAL-NODE: PASS" || echo "REAL-NODE: FAIL"
exit $fail
