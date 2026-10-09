#!/usr/bin/env python3
"""netem-proxy.py -- a UDP impairment proxy: loss, delay, jitter, duplication.

Test tooling only (the kernel's netem needs root).  It listens on LISTEN and
forwards every datagram to TARGET; replies from TARGET go back to whichever
client address last sent.  Each datagram, in each direction independently, is
dropped with probability LOSS, delayed by DELAY +- JITTER ms (uniform, so
jitter also REORDERS), and sent twice with probability DUP.  Seeded, so a run
can be repeated.

  netem-proxy.py --listen 127.0.0.1:0 --target 127.0.0.1:2121 \
                 --loss 0.05 --delay 50 --jitter 30 --dup 0.01 --seed 1 --port-file F

The bound port is written to --port-file once listening.  On SIGTERM it prints
counts (forwarded / dropped / duplicated per direction) to stderr and exits.
"""
import argparse, heapq, random, select, signal, socket, sys, time

def hostport(s):
    h, p = s.rsplit(":", 1)
    return (h, int(p))

ap = argparse.ArgumentParser()
ap.add_argument("--listen", type=hostport, required=True)
ap.add_argument("--target", type=hostport, required=True)
ap.add_argument("--loss", type=float, default=0.0)
ap.add_argument("--delay", type=float, default=0.0, help="ms")
ap.add_argument("--jitter", type=float, default=0.0, help="ms, uniform +-")
ap.add_argument("--dup", type=float, default=0.0)
ap.add_argument("--seed", type=int, default=1)
ap.add_argument("--port-file")
a = ap.parse_args()

rng = random.Random(a.seed)
target = (socket.gethostbyname(a.target[0]), a.target[1])
front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)   # clients talk to this
front.bind(a.listen)
back = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)    # we talk to the target from this
back.bind(("0.0.0.0" if target[0] not in ("127.0.0.1",) else "127.0.0.1", 0))
if a.port_file:
    with open(a.port_file, "w") as f:
        f.write(str(front.getsockname()[1]))

client = None
queue = []            # (due, seq, sock, data, addr)
seq = 0
stats = {"up": [0, 0, 0], "down": [0, 0, 0]}   # forwarded, dropped, duplicated

def schedule(sock, data, addr, way):
    global seq
    if rng.random() < a.loss:
        stats[way][1] += 1
        return
    copies = 2 if rng.random() < a.dup else 1
    if copies == 2:
        stats[way][2] += 1
    for _ in range(copies):
        d = max(0.0, a.delay + rng.uniform(-a.jitter, a.jitter)) / 1000.0
        seq += 1
        heapq.heappush(queue, (time.monotonic() + d, seq, sock, data, addr))
    stats[way][0] += 1

def done(*_):
    for way in ("up", "down"):
        f, d, u = stats[way]
        print(f"netem {way}: forwarded {f} dropped {d} duplicated {u}", file=sys.stderr)
    sys.exit(0)

signal.signal(signal.SIGTERM, done)
signal.signal(signal.SIGINT, done)

while True:
    timeout = max(0.0, queue[0][0] - time.monotonic()) if queue else 0.5
    r, _, _ = select.select([front, back], [], [], timeout)
    for s in r:
        data, addr = s.recvfrom(65536)
        if s is front:
            client = addr
            schedule(back, data, target, "up")
        elif client is not None:
            schedule(front, data, client, "down")
    now = time.monotonic()
    while queue and queue[0][0] <= now:
        _, _, sock, data, addr = heapq.heappop(queue)
        try:
            sock.sendto(data, addr)
        except OSError:
            pass
