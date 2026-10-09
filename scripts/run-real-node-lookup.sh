#!/bin/sh
# run-real-node-lookup.sh -- coordinate discovery against REAL upstream nodes, over UDP.
#
#   FIPS_BIN=/path/to/fips scripts/run-real-node-lookup.sh [SECS]
#
# Topology, every link UDP on 127.0.0.1:
#
#     Lisp ---- A (relay) ---- B (native-echo on 4600)
#                  \
#                   `--------- C (native-send to the daemon's npub, port 4700)
#
# Lisp's only peer is A, and it is given B only as an npub.  Nobody tells anyone
# coordinates, so each direction needs a lookup:
#   Lisp -> B  the daemon looks B up through A, verifies B's proof, opens the
#              session with B's coordinates, and B echoes our probes
#   C -> Lisp  C looks the daemon up through A; the daemon answers with a signed
#              proof, C verifies it ("Discovery succeeded, proof verified"), opens
#              a session, and its datagram reaches us
# B and C are different nodes on purpose: a session in one direction would hand
# the other side our coordinates and hide a broken lookup.
set -u
SECS=${1:-45}
if [ -z "${FIPS_BIN:-}" ] || [ ! -x "${FIPS_BIN:-}" ]; then
  echo "SKIPPED: set FIPS_BIN to an upstream fips binary (jmcorgan/fips @ 57bc510)"
  exit 0
fi
HERE=$(cd "$(dirname "$0")/.." && pwd)
DIR=$(mktemp -d /tmp/cl-fips-lookup.XXXXXX)
NODE="$HERE/scripts/cl-fips-node"
LISP="sbcl --script $HERE/test/daemon-real-node.lisp"
ECHO_BIN="${ECHO_BIN:-$(dirname "$FIPS_BIN")/examples/native-echo}"
SEND_BIN="${SEND_BIN:-$(dirname "$FIPS_BIN")/examples/native-send}"
free_udp() { python3 -I -c 'import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
fail=0
for b in "$ECHO_BIN" "$SEND_BIN"; do [ -x "$b" ] || { echo "FAIL: $b is not built"; exit 1; }; done

for k in a b c lisp; do "$NODE" keygen "$DIR/$k.key" > /dev/null || { echo "FAIL: keygen $k"; exit 1; }; done
PA=$(free_udp); PB=$(free_udp); PC=$(free_udp); PL=$(free_udp)

node_yaml() {  # $1 name, $2 port, $3 "peer" to dial A, else nothing
  {
    echo "node:"
    echo "  identity:"
    echo "    nsec: \"$(head -1 "$DIR/$1.key")\""
    echo "  log_level: trace"
    echo "  control:"
    echo "    socket_path: \"$DIR/$1-control.sock\""
    echo "  native_api:"
    echo "    enabled: true"
    echo "    socket_path: \"$DIR/$1-api.sock\""
    echo "tun:"
    echo "  enabled: false"
    echo "dns:"
    echo "  enabled: false"
    echo "transports:"
    echo "  udp:"
    echo "    bind_addr: \"127.0.0.1:$2\""
    if [ -n "${3:-}" ]; then
      echo "peers:"
      echo "  - npub: \"$(cat "$DIR/a.pub")\""
      echo "    alias: \"relay\""
      echo "    addresses:"
      echo "      - transport: udp"
      echo "        addr: \"127.0.0.1:$PA\""
    fi
  } > "$DIR/$1.yaml"
}
node_yaml a "$PA"
node_yaml b "$PB" peer
node_yaml c "$PC" peer
cat > "$DIR/lisp.conf" <<EOF
(:identity (:key-file "$DIR/lisp.key")
 :udp (:bind "127.0.0.1:$PL")
 :peers ((:npub "$(cat "$DIR/a.pub")" :transport :udp :addr "127.0.0.1:$PA" :alias "relay")))
EOF

"$FIPS_BIN" -c "$DIR/a.yaml" > "$DIR/a.log" 2>&1 & PIDA=$!
i=0; until grep -q "UDP receive loop starting" "$DIR/a.log" || [ $i -ge 50 ]; do sleep 0.2; i=$((i+1)); done
"$FIPS_BIN" -c "$DIR/b.yaml" > "$DIR/b.log" 2>&1 & PIDB=$!
"$FIPS_BIN" -c "$DIR/c.yaml" > "$DIR/c.log" 2>&1 & PIDC=$!
i=0; until [ -S "$DIR/b-api.sock" ] || [ $i -ge 50 ]; do sleep 0.2; i=$((i+1)); done
"$ECHO_BIN" "$DIR/b-api.sock" 4600 > "$DIR/echo.log" 2>&1 & PIDE=$!
i=0; until grep -q "accepting on port" "$DIR/echo.log" 2>/dev/null || [ $i -ge 50 ]; do sleep 0.2; i=$((i+1)); done
sleep 3                                  # B and C link to A and the tree settles

echo "== Lisp -> A -> B by lookup, and C -> A -> Lisp by lookup (${SECS}s)"
timeout $((SECS + 60)) $LISP "$DIR/lisp.conf" "$(cat "$DIR/b.pub")" "$SECS" > "$DIR/lisp.log" 2>&1 & PIDL=$!
# C's flow to the daemon, once the daemon has linked to A and announced itself
( i=0; until grep -q "peer-up" "$DIR/lisp.log" 2>/dev/null || [ $i -ge 300 ]; do sleep 0.2; i=$((i+1)); done
  sleep 5
  "$SEND_BIN" "$DIR/c-api.sock" "$(cat "$DIR/lisp.pub")" 4700 "from-c-by-lookup" > "$DIR/send.log" 2>&1 ) &
wait $PIDL || fail=1
kill $PIDE $PIDC $PIDB $PIDA 2>/dev/null; wait 2>/dev/null

grep -E "lookup-ok|lookup-answered|lookup-failed|probes sent|PASS|FAIL" "$DIR/lisp.log" | sed 's/^/  /' | cut -c1-160
if grep -q "lookup-ok" "$DIR/lisp.log"; then echo "  daemon: looked B up and verified B's proof"
else echo "  FAIL: the daemon's lookup of B did not succeed"; fail=1; fi
if grep -q "Session established" "$DIR/b.log"; then echo "  B: session established with the daemon, through A"
else echo "  FAIL: B established no session"; fail=1; fi
if grep -q "lookup-answered" "$DIR/lisp.log"; then echo "  daemon: answered a LookupRequest for itself"
else echo "  FAIL: the daemon answered no LookupRequest"; fail=1; fi
if grep -q "Discovery succeeded, proof verified" "$DIR/c.log"; then echo "  C: verified the daemon's lookup proof"
else echo "  FAIL: C did not verify a lookup proof from the daemon"; fail=1; fi
if grep -q 'DATA from .* dst_port=4700 data="from-c-by-lookup"' "$DIR/lisp.log"; then
  echo "  C -> daemon: the datagram arrived, byte for byte"
else echo "  FAIL: C's datagram did not reach the daemon"; fail=1; fi
echo "logs: $DIR"
[ $fail -eq 0 ] && echo "REAL-NODE-LOOKUP: PASS" || echo "REAL-NODE-LOOKUP: FAIL"
exit $fail
