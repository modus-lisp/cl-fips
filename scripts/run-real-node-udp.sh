#!/bin/sh
# run-real-node-udp.sh -- the cl-fips DAEMON against a REAL upstream node over UDP.
#
#   FIPS_BIN=/path/to/fips scripts/run-real-node-udp.sh [SECS]
#
# Two arms, fresh keys each run, everything on 127.0.0.1:
#   dial    the node binds UDP; the daemon's config names it as a peer and dials it
#   accept  the daemon binds UDP; the node's config names the daemon and dials it
# In both, once the link is up the daemon opens an FSP session to the node and
# sends a probe to its native-echo (port 4600) every 2 s; each must come back
# byte for byte.  A native-send on the node opens a flow to the daemon's npub
# (port 4700), which must arrive.  The node's own log must show the peer
# promoted, our heartbeats, the session established, our ReceiverReports
# processed, and no peer removed.  Without FIPS_BIN this prints SKIPPED.
set -u
SECS=${1:-40}
if [ -z "${FIPS_BIN:-}" ] || [ ! -x "${FIPS_BIN:-}" ]; then
  echo "SKIPPED: set FIPS_BIN to an upstream fips binary (jmcorgan/fips @ 57bc510)"
  exit 0
fi
HERE=$(cd "$(dirname "$0")/.." && pwd)
DIR=$(mktemp -d /tmp/cl-fips-real-node-udp.XXXXXX)
NODE="$HERE/scripts/cl-fips-node"
LISP="sbcl --script $HERE/test/daemon-real-node.lisp"
ECHO_BIN="${ECHO_BIN:-$(dirname "$FIPS_BIN")/examples/native-echo}"
SEND_BIN="${SEND_BIN:-$(dirname "$FIPS_BIN")/examples/native-send}"
free_udp() { python3 -I -c 'import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
fail=0

node_yaml() {  # $1 file, $2 arm dir, $3 node udp port, $4 optional lisp udp port
  {
    echo "node:"
    echo "  identity:"
    echo "    nsec: \"$(head -1 "$DIR/node.key")\""
    echo "  log_level: trace"
    echo "  control:"
    echo "    socket_path: \"$2/control.sock\""
    echo "  native_api:"
    echo "    enabled: true"
    echo "    socket_path: \"$2/api.sock\""
    echo "tun:"
    echo "  enabled: false"
    echo "dns:"
    echo "  enabled: false"
    echo "transports:"
    echo "  udp:"
    echo "    bind_addr: \"127.0.0.1:$3\""
    if [ -n "${4:-}" ]; then
      echo "peers:"
      echo "  - npub: \"$(cat "$DIR/lisp.pub")\""
      echo "    alias: \"cl-fips\""
      echo "    addresses:"
      echo "      - transport: udp"
      echo "        addr: \"127.0.0.1:$4\""
    fi
  } > "$1"
}

lisp_conf() {  # $1 file, $2 lisp udp port, $3 optional node udp port
  {
    echo "(:identity (:key-file \"$DIR/lisp.key\")"
    echo " :udp (:bind \"127.0.0.1:$2\")"
    [ -n "${3:-}" ] && echo " :peers ((:npub \"$NODE_NPUB\" :transport :udp :addr \"127.0.0.1:$3\" :alias \"node\"))"
    echo ")"
  } > "$1"
}

check_node_log() {  # $1 log
  if grep -q "Connection promoted to active peer" "$1"; then echo "  node: peer promoted to active"
  else echo "  FAIL: node never promoted the peer"; fail=1; fi
  hb=$(grep -c "Received heartbeat" "$1")
  if [ "$hb" -ge 1 ]; then echo "  node: received $hb heartbeats from the daemon"
  else echo "  FAIL: node logged no heartbeat"; fail=1; fi
  rr=$(grep -c "Processed ReceiverReport" "$1")
  if [ "$rr" -ge 1 ]; then echo "  node: processed $rr ReceiverReports"
  else echo "  FAIL: node processed no ReceiverReport"; fail=1; fi
  if grep -q "Session established" "$1"; then echo "  node: FSP session established"
  else echo "  FAIL: node established no FSP session"; fail=1; fi
  if grep -qE "Removing peer|Peer removed" "$1"; then echo "  FAIL: node removed the peer"; fail=1
  else echo "  node: never removed the peer"; fi
}

start_helpers() {  # $1 arm dir
  i=0; until [ -S "$1/api.sock" ] || [ $i -ge 50 ]; do sleep 0.2; i=$((i+1)); done
  EP=""; SP=""
  if [ -x "$ECHO_BIN" ]; then
    "$ECHO_BIN" "$1/api.sock" 4600 > "$1/echo.log" 2>&1 &
    EP=$!
    i=0; until grep -q "accepting on port" "$1/echo.log" 2>/dev/null || [ $i -ge 50 ]; do sleep 0.2; i=$((i+1)); done
  else echo "  FAIL: native-echo is not built at $ECHO_BIN"; fail=1; fi
  if [ -x "$SEND_BIN" ]; then
    ( i=0; until grep -q "Session established" "$1/node.log" 2>/dev/null || [ $i -ge 150 ]; do sleep 0.2; i=$((i+1)); done
      sleep 2
      "$SEND_BIN" "$1/api.sock" "$(cat "$DIR/lisp.pub")" 4700 "from-node-over-udp" > "$1/send.log" 2>&1 ) &
    SP=$!
  fi
}

check_lisp_log() {  # $1 log
  grep -E "probes sent|PASS|FAIL|MISMATCH" "$1" | sed 's/^/  /'
  if [ -x "$SEND_BIN" ]; then
    if grep -q 'DATA from the node src_port=.* dst_port=4700 data="from-node-over-udp"' "$1"; then
      echo "  node-initiated: the node's flow reached the daemon over UDP (port 4700)"
    else echo "  FAIL: no node-initiated DataPacket reached the daemon"; fail=1; fi
  fi
}

"$NODE" keygen "$DIR/node.key" > /dev/null || { echo "FAIL: keygen"; exit 1; }
"$NODE" keygen "$DIR/lisp.key" > /dev/null || { echo "FAIL: keygen"; exit 1; }
NODE_NPUB=$(cat "$DIR/node.pub")

for arm in dial accept; do
  A="$DIR/$arm"; mkdir -p "$A"
  NPORT=$(free_udp); LPORT=$(free_udp)
  if [ $arm = dial ]; then
    node_yaml "$A/node.yaml" "$A" "$NPORT"
    lisp_conf "$A/lisp.conf" "$LPORT" "$NPORT"
  else
    node_yaml "$A/node.yaml" "$A" "$NPORT" "$LPORT"
    lisp_conf "$A/lisp.conf" "$LPORT"
  fi
  echo "== $arm (node udp 127.0.0.1:$NPORT, daemon udp 127.0.0.1:$LPORT)"
  if [ $arm = accept ]; then
    timeout $((SECS + 60)) $LISP "$A/lisp.conf" "$NODE_NPUB" "$SECS" > "$A/lisp.log" 2>&1 &
    LP=$!
    i=0; until grep -q LISTENING "$A/lisp.log" 2>/dev/null || [ $i -ge 300 ]; do sleep 0.2; i=$((i+1)); done
  fi
  "$FIPS_BIN" -c "$A/node.yaml" > "$A/node.log" 2>&1 &
  NP=$!
  i=0; until grep -q "UDP receive loop starting" "$A/node.log" || [ $i -ge 50 ]; do sleep 0.2; i=$((i+1)); done
  start_helpers "$A"
  if [ $arm = dial ]; then
    timeout $((SECS + 60)) $LISP "$A/lisp.conf" "$NODE_NPUB" "$SECS" > "$A/lisp.log" 2>&1 || fail=1
  else
    wait $LP || fail=1
  fi
  kill $NP 2>/dev/null; wait $NP 2>/dev/null
  [ -n "$EP" ] && kill $EP 2>/dev/null; [ -n "$SP" ] && kill $SP 2>/dev/null
  check_lisp_log "$A/lisp.log"
  check_node_log "$A/node.log"
done

echo "logs: $DIR"
[ $fail -eq 0 ] && echo "REAL-NODE-UDP: PASS" || echo "REAL-NODE-UDP: FAIL"
exit $fail
