#!/bin/sh
# run-modus-node.sh -- a cl-fips node running inside MODUS, against a real FIPS node.
#
#   FIPS_BIN=/path/to/fips MODUS_BIN=/path/to/modus [TRANSPORT=udp|tcp] \
#     scripts/run-modus-node.sh [SECS] [dial|accept]
# ROUNDS=N (accept arm): the upstream node is started, killed and started again N
# times against the one modus node, with the same identity, and each round reports
# how long the node took to promote us and whether a session and echoes came back.
#
# dial    the modus node's config names the upstream node; it dials it over UDP.
# accept  the upstream node's config names the modus node; it dials modus.
# Either way the modus node opens an FSP session to the upstream node and its
# native-echo (port 4600) must return the probes, and the node's log must show
# the peer promoted, our heartbeats and ReceiverReports, the session, and no
# removal.  MODUS_BIN needs the sb-bsd-sockets UDP support (sendto / recvfrom /
# wait-until-fd-usable) in net/sb-sys-shim.lisp.
set -u
SECS=${1:-60}
ARM=${2:-dial}
T=${TRANSPORT:-udp}
HERE=$(cd "$(dirname "$0")/.." && pwd)
DIR=$(mktemp -d /tmp/cl-fips-modus-node.XXXXXX)
NODE="$HERE/scripts/cl-fips-node"
ECHO_BIN="${ECHO_BIN:-$(dirname "${FIPS_BIN:-/x}")/examples/native-echo}"
for b in "${FIPS_BIN:-}" "${MODUS_BIN:-}" "$ECHO_BIN"; do
  [ -n "$b" ] && [ -x "$b" ] || { echo "SKIPPED: set FIPS_BIN and MODUS_BIN (and build native-echo)"; exit 0; }
done
free_tcp() { python3 -I -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
free_udp() { python3 -I -c 'import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
"$NODE" keygen "$DIR/node.key" > /dev/null && "$NODE" keygen "$DIR/modus.key" > /dev/null || exit 1
if [ "$T" = tcp ]; then NPORT=$(free_tcp); MPORT=$(free_tcp); else NPORT=$(free_udp); MPORT=$(free_udp); fi
{
  echo "node:"; echo "  identity:"; echo "    nsec: \"$(head -1 "$DIR/node.key")\""
  echo "  log_level: trace"
  echo "  control:"; echo "    socket_path: \"$DIR/control.sock\""
  echo "  native_api:"; echo "    enabled: true"; echo "    socket_path: \"$DIR/api.sock\""
  echo "tun:"; echo "  enabled: false"; echo "dns:"; echo "  enabled: false"
  echo "transports:"; echo "  $T:"; echo "    bind_addr: \"127.0.0.1:$NPORT\""
  if [ "$ARM" = accept ]; then
    echo "peers:"; echo "  - npub: \"$(cat "$DIR/modus.pub")\""; echo "    alias: \"modus\""
    echo "    addresses:"; echo "      - transport: $T"; echo "        addr: \"127.0.0.1:$MPORT\""
  fi
} > "$DIR/node.yaml"
if [ "$ARM" = dial ]; then
  PEERS="((:npub \"$(cat "$DIR/node.pub")\" :transport :$T :addr \"127.0.0.1:$NPORT\" :alias \"node\"))"
else
  PEERS="()"
fi
echo "(:identity (:key-file \"$DIR/modus.key\") :$T (:bind \"127.0.0.1:$MPORT\") :peers $PEERS)" > "$DIR/modus.conf"

start_node() {
  "$FIPS_BIN" -c "$DIR/node.yaml" > "$DIR/node${1:-}.log" 2>&1 & NP=$!
  i=0; until [ -S "$DIR/api.sock" ] || [ $i -ge 50 ]; do sleep 0.2; i=$((i+1)); done
  "$ECHO_BIN" "$DIR/api.sock" 4600 > "$DIR/echo.log" 2>&1 & EP=$!
}
echo "== a cl-fips node on modus ($ARM, $T), ${SECS}s"
# The node dials the moment it starts, so in the accept arm it starts only once the
# modus node is LISTENING: loading the libraries from source takes modus ~15 s, and
# a node that dials into nothing backs off (UDP: resends at 1/3/8/17 s, then a 30 s
# handshake timeout and a 10 s wait; TCP: refused, then retries 10 s and 20 s apart).
[ "$ARM" = dial ] && start_node
MODUS_FIPS_CONFIG="$DIR/modus.conf" MODUS_FIPS_TARGET="$(cat "$DIR/node.pub")" MODUS_FIPS_SECS="$SECS" \
  timeout $((SECS + 900)) "$MODUS_BIN" --script "$HERE/test/modus-node.lisp" > "$DIR/modus.log" 2>&1 &
MP=$!
if [ "$ARM" = accept ]; then
  i=0; until grep -aq LISTENING "$DIR/modus.log" 2>/dev/null || [ $i -ge 600 ]; do sleep 0.2; i=$((i+1)); done
  R=${ROUNDS:-1}
  if [ "$R" -gt 1 ]; then
    for r in $(seq 1 $R); do
      t0=$(date +%s.%N)
      start_node "-$r"
      i=0; until grep -aq "Connection promoted to active peer" "$DIR/node-$r.log" || [ $i -ge 600 ]; do sleep 0.1; i=$((i+1)); done
      t1=$(date +%s.%N)
      i=0; until grep -aq "Session established" "$DIR/node-$r.log" || [ $i -ge 300 ]; do sleep 0.1; i=$((i+1)); done
      t2=$(date +%s.%N)
      sleep ${HOLD:-10}
      echoes=$(grep -ac "Native API flow closed by its client local=4600" "$DIR/node-$r.log")
      printf '  round %d: promoted %.1f s after start, session %.1f s, %d echoes served\n' \
        $r $(echo "$t1 - $t0" | bc) $(echo "$t2 - $t0" | bc) "$echoes"
      kill $EP $NP 2>/dev/null; wait $EP $NP 2>/dev/null
      sleep 1
    done
    cp "$DIR/node-$R.log" "$DIR/node.log"
    kill $MP 2>/dev/null
  else
    start_node
  fi
fi
wait $MP
rc=$?
[ "${ROUNDS:-1}" -gt 1 ] && rc=0
kill $EP $NP 2>/dev/null; wait $EP $NP 2>/dev/null
grep -aE "LOADED|LOAD FAILED|LISTENING|peer-up|established|probes sent|PASS|FAIL" "$DIR/modus.log" | grep -v "^ *[0-9.]* frame" | head -12 | sed 's/^/  /'
fail=$rc
check() { if grep -qE "$2" "$DIR/node.log"; then echo "  node: $1"; else echo "  FAIL: node: $1"; fail=1; fi; }
check "peer promoted to active" "Connection promoted to active peer"
check "heartbeats from the modus node" "Received heartbeat"
check "ReceiverReports from the modus node" "Processed ReceiverReport"
check "FSP session established" "Session established"
if grep -qE "Removing peer|Peer removed" "$DIR/node.log"; then echo "  FAIL: node removed the peer"; fail=1; fi
echo "logs: $DIR"
[ "$fail" -eq 0 ] && echo "MODUS-NODE: PASS" || echo "MODUS-NODE: FAIL"
exit "$fail"
