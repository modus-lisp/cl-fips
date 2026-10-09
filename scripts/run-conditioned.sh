#!/bin/sh
# run-conditioned.sh -- cl-fips over an impaired network: loss, delay, jitter, duplication.
#
#   FIPS_BIN=/path/to/fips scripts/run-conditioned.sh [PROFILE ...]
#
# Profiles (each direction independently):
#   clean   no impairment (the control)
#   lossy   5% loss, 40 +- 20 ms
#   bad     15% loss, 80 +- 60 ms (reorders), 2% duplicated
#   awful   30% loss, 150 +- 100 ms, 5% duplicated
#
# Each profile runs two scenarios (three with MESH=1) through scripts/netem-proxy.py:
#   echo    the daemon dials the REAL upstream node over UDP through the proxy,
#           opens a session and sends a probe to its native-echo every 2 s.  FIPS
#           DataPackets are datagrams -- a lost probe is lost -- so the pass bar is
#           the link and session coming up and staying up, at least 3 echoes, and
#           no echo that differs from what was sent.
#   stream  seal fetches a 1 MiB random file over cl-fips's stream protocol:
#           client node --proxy--> gateway node -> a local HTTP server.  The stream
#           is reliable, so the bar is exact: the SHA-256 of what arrives must equal
#           the file's.
#   mesh    (MESH=1; needs the internet) the proxy sits between us and test-us01 on the
#           PUBLIC test mesh, and cl-transport/tcp reads test-us01's SSH banner over the
#           IPv6 shim.  The public path adds its own loss on top of the profile's.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
DIR=$(mktemp -d /tmp/cl-fips-conditioned.XXXXXX)
NODE="$HERE/scripts/cl-fips-node"
PROXY="python3 -I $HERE/scripts/netem-proxy.py"
ECHO_BIN="${ECHO_BIN:-$(dirname "${FIPS_BIN:-/nonexistent}")/examples/native-echo}"
free_udp() { python3 -I -c 'import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
free_tcp() { python3 -I -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
fail=0
PROFILES=${*:-clean lossy bad awful}

params() {
  case $1 in
    clean) echo "--loss 0 --delay 0 --jitter 0 --dup 0" ;;
    lossy) echo "--loss 0.05 --delay 40 --jitter 20 --dup 0" ;;
    bad)   echo "--loss 0.15 --delay 80 --jitter 60 --dup 0.02" ;;
    awful) echo "--loss 0.30 --delay 150 --jitter 100 --dup 0.05" ;;
    *) echo "unknown profile $1" >&2; exit 2 ;;
  esac
}

start_proxy() {  # $1 profile, $2 target port, $3 port file, $4 log
  $PROXY --listen 127.0.0.1:0 --target "127.0.0.1:$2" $(params "$1") --seed "${SEED:-1}" --port-file "$3" 2> "$4" &
  PROXY_PID=$!
  i=0; until [ -s "$3" ] || [ $i -ge 50 ]; do sleep 0.1; i=$((i+1)); done
}

# the file the stream scenario fetches, served by a local HTTP server
mkdir -p "$DIR/www"
head -c 1048576 /dev/urandom > "$DIR/www/blob"
SHA=$(sha256sum "$DIR/www/blob" | cut -d' ' -f1)
HTTP_PORT=$(free_tcp)
python3 -I -m http.server "$HTTP_PORT" --bind 127.0.0.1 --directory "$DIR/www" > "$DIR/http.log" 2>&1 &
HTTP_PID=$!
sleep 1

for k in node lisp gw client; do "$NODE" keygen "$DIR/$k.key" > /dev/null || exit 1; done
SUMMARY=""

for prof in $PROFILES; do
  P="$DIR/$prof"; mkdir -p "$P"
  echo "== $prof: $(params "$prof")"

  # --- echo: the daemon against the real node, through the proxy -------------
  if [ "${ECHO:-1}" = 1 ] && [ -n "${FIPS_BIN:-}" ] && [ -x "$FIPS_BIN" ] && [ -x "$ECHO_BIN" ]; then
    NPORT=$(free_udp)
    cat > "$P/node.yaml" <<EOF
node:
  identity:
    nsec: "$(head -1 "$DIR/node.key")"
  log_level: debug
  control:
    socket_path: "$P/control.sock"
  native_api:
    enabled: true
    socket_path: "$P/api.sock"
tun:
  enabled: false
dns:
  enabled: false
transports:
  udp:
    bind_addr: "127.0.0.1:$NPORT"
EOF
    "$FIPS_BIN" -c "$P/node.yaml" > "$P/node.log" 2>&1 & NPID=$!
    i=0; until [ -S "$P/api.sock" ] || [ $i -ge 50 ]; do sleep 0.2; i=$((i+1)); done
    "$ECHO_BIN" "$P/api.sock" 4600 > "$P/echo.log" 2>&1 & EPID=$!
    start_proxy "$prof" "$NPORT" "$P/echo-proxy.port" "$P/echo-proxy.log"
    cat > "$P/lisp.conf" <<EOF
(:identity (:key-file "$DIR/lisp.key") :udp (:bind "127.0.0.1:0")
 :peers ((:npub "$(cat "$DIR/node.pub")" :transport :udp :addr "127.0.0.1:$(cat "$P/echo-proxy.port")")))
EOF
    timeout 200 sbcl --script "$HERE/test/daemon-real-node.lisp" "$P/lisp.conf" "$(cat "$DIR/node.pub")" "${ECHO_SECS:-60}" \
      > "$P/echo-lisp.log" 2>&1
    erc=$?
    kill $PROXY_PID $EPID $NPID 2>/dev/null; wait $PROXY_PID $EPID $NPID 2>/dev/null
    res=$(grep "probes sent" "$P/echo-lisp.log")
    downs=$(grep -c "peer-down\|link-closed" "$P/echo-lisp.log")
    removed=$(grep -cE "Removing peer|Peer removed" "$P/node.log")
    if [ $erc -eq 0 ] && [ "$downs" -eq 0 ] && [ "$removed" -eq 0 ]; then r=PASS; else r=FAIL; fail=1; fi
    echo "  echo   $r: $res; link drops $downs; node removed peer $removed"
    sed 's/^/           /' "$P/echo-proxy.log"
    SUMMARY="$SUMMARY
$prof echo $r ($res)"
  else
    echo "  echo   SKIPPED (FIPS_BIN / native-echo not built)"
  fi

  # --- stream: a 1 MiB file over the stream protocol, through the proxy ------
  if [ "${STREAM:-1}" = 1 ]; then
  GPORT=$(free_udp)
  cat > "$P/gw.conf" <<EOF
(:identity (:key-file "$DIR/gw.key") :udp (:bind "127.0.0.1:$GPORT"))
EOF
  sbcl --script "$HERE/test/seal-over-fips.lisp" gateway "$P/gw.conf" "$(cat "$DIR/client.pub")" > "$P/gw.log" 2>&1 & GWPID=$!
  i=0; until grep -q GATEWAY "$P/gw.log" 2>/dev/null || [ $i -ge 300 ]; do sleep 0.2; i=$((i+1)); done
  start_proxy "$prof" "$GPORT" "$P/stream-proxy.port" "$P/stream-proxy.log"
  cat > "$P/client.conf" <<EOF
(:identity (:key-file "$DIR/client.key") :udp (:bind "127.0.0.1:0")
 :peers ((:npub "$(cat "$DIR/gw.pub")" :transport :udp :addr "127.0.0.1:$(cat "$P/stream-proxy.port")")))
EOF
  timeout "${STREAM_TIMEOUT:-600}" sbcl --script "$HERE/test/seal-over-fips.lisp" client "$P/client.conf" "$(cat "$DIR/gw.pub")" \
    "http://127.0.0.1:$HTTP_PORT/blob" "sha256:$SHA" > "$P/stream-client.log" 2>&1
  src=$?
  kill $PROXY_PID $GWPID 2>/dev/null; wait $PROXY_PID $GWPID 2>/dev/null
  line=$(grep -aE "^HTTP|FETCH FAILED" "$P/stream-client.log" | head -1)
  if [ $src -eq 0 ]; then r=PASS; else r=FAIL; fail=1; fi
  echo "  stream $r: ${line:-no result (rc=$src)}"
  sed 's/^/           /' "$P/stream-proxy.log"
  SUMMARY="$SUMMARY
$prof stream $r (${line:-rc=$src})"
  fi
  # --- mesh: TCP over the shim to the public mesh, through the proxy ----------
  if [ "${MESH:-0}" = 1 ]; then
    MESH_IP=$(python3 -I -c 'import socket;print(socket.gethostbyname("test-us01.fips.network"))')
    $PROXY --listen 127.0.0.1:0 --target "$MESH_IP:2121" $(params "$prof") --seed "${SEED:-1}" \
      --port-file "$P/mesh-proxy.port" 2> "$P/mesh-proxy.log" &
    PROXY_PID=$!
    i=0; until [ -s "$P/mesh-proxy.port" ] || [ $i -ge 50 ]; do sleep 0.1; i=$((i+1)); done
    MESH_PEER_ADDR="127.0.0.1:$(cat "$P/mesh-proxy.port")" timeout 300 sbcl --script "$HERE/test/mesh-banner.lisp" \
      > "$P/mesh.log" 2>&1
    mrc=$?
    kill $PROXY_PID 2>/dev/null; wait $PROXY_PID 2>/dev/null
    if [ $mrc -eq 0 ]; then r=PASS; else r=FAIL; fail=1; fi
    echo "  mesh   $r: $(grep -a '^npub' "$P/mesh.log" | head -1)"
    sed 's/^/           /' "$P/mesh-proxy.log"
    SUMMARY="$SUMMARY
$prof mesh $r"
  fi
done

kill $HTTP_PID 2>/dev/null
echo "$SUMMARY" | sed '/^$/d' > "$DIR/summary.txt"
echo "logs: $DIR"
[ $fail -eq 0 ] && echo "CONDITIONED: PASS" || echo "CONDITIONED: FAIL"
exit $fail
