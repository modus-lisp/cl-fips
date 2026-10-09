#!/bin/sh
# run-seal-over-fips.sh -- seal fetches an https URL; the bytes go over FIPS.
#
#   FIPS_BIN=/path/to/fips scripts/run-seal-over-fips.sh [URL] [EXPECT]
#
#     seal (TLS) -> cl-transport :fips -> Lisp client --UDP--> upstream relay A
#                --UDP--> Lisp gateway -> TCP -> the web server
#
# The client and the gateway are cl-fips nodes; A is the real upstream node, and
# neither Lisp node is told the other's coordinates (the client looks the gateway
# up through A).  The stream protocol on top is cl-fips's own (both ends are
# cl-fips); TLS runs from seal to the server, so A and the gateway carry only
# ciphertext.  Without FIPS_BIN, the gateway is the client's direct peer instead.
set -u
URL=${1:-https://example.com/}
EXPECT=${2:-Example Domain}
HERE=$(cd "$(dirname "$0")/.." && pwd)
DIR=$(mktemp -d /tmp/cl-fips-seal.XXXXXX)
NODE="$HERE/scripts/cl-fips-node"
LISP="sbcl --script $HERE/test/seal-over-fips.lisp"
free_udp() { python3 -I -c 'import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
for k in a gw client; do "$NODE" keygen "$DIR/$k.key" > /dev/null || exit 1; done
PA=$(free_udp); PG=$(free_udp); PC=$(free_udp)

if [ -n "${FIPS_BIN:-}" ] && [ -x "$FIPS_BIN" ]; then
  RELAY="(:npub \"$(cat "$DIR/a.pub")\" :transport :udp :addr \"127.0.0.1:$PA\" :alias \"relay\")"
  cat > "$DIR/a.yaml" <<EOF
node:
  identity:
    nsec: "$(head -1 "$DIR/a.key")"
  log_level: debug
  control:
    socket_path: "$DIR/a-control.sock"
tun:
  enabled: false
dns:
  enabled: false
transports:
  udp:
    bind_addr: "127.0.0.1:$PA"
EOF
  "$FIPS_BIN" -c "$DIR/a.yaml" > "$DIR/a.log" 2>&1 & PIDA=$!
  i=0; until grep -q "UDP receive loop starting" "$DIR/a.log" || [ $i -ge 50 ]; do sleep 0.2; i=$((i+1)); done
  GW_PEERS="($RELAY)"; CLIENT_PEERS="($RELAY)"
  echo "== seal -> Lisp client -> upstream relay A -> Lisp gateway -> $URL"
else
  PIDA=""
  GW_PEERS="()"
  CLIENT_PEERS="((:npub \"$(cat "$DIR/gw.pub")\" :transport :udp :addr \"127.0.0.1:$PG\" :alias \"gateway\"))"
  echo "== (no FIPS_BIN: no relay) seal -> Lisp client -> Lisp gateway -> $URL"
fi
cat > "$DIR/gw.conf" <<EOF
(:identity (:key-file "gw.key") :udp (:bind "127.0.0.1:$PG") :peers $GW_PEERS)
EOF
cat > "$DIR/client.conf" <<EOF
(:identity (:key-file "client.key") :udp (:bind "127.0.0.1:$PC") :peers $CLIENT_PEERS)
EOF

$LISP gateway "$DIR/gw.conf" "$(cat "$DIR/client.pub")" > "$DIR/gw.log" 2>&1 & PIDG=$!
i=0; until grep -q GATEWAY "$DIR/gw.log" 2>/dev/null || [ $i -ge 300 ]; do sleep 0.2; i=$((i+1)); done
sleep 2
timeout 180 $LISP client "$DIR/client.conf" "$(cat "$DIR/gw.pub")" "$URL" "$EXPECT" > "$DIR/client.log" 2>&1
rc=$?
kill $PIDG ${PIDA:-} 2>/dev/null; wait 2>/dev/null
grep -vE "^(WARNING|;|  )" "$DIR/client.log" | grep -E "CLIENT|HTTP|PASS|FAIL|<" | head -12 | sed 's/^/  /'
if [ -n "$PIDA" ]; then
  fw=$(grep -c "Forwarding\|forward" "$DIR/a.log")
  echo "  relay A: $fw forwarding log lines"
fi
echo "logs: $DIR"
exit $rc
