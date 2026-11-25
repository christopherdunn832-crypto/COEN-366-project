"""
fake_subscriber.py  -  Minimal test client for Part B (not C's real client).

    python fake_subscriber.py NAME UDP_PORT [SERVER_HOST] [SERVER_PORT] [--drop N]

Prints everything it receives, auto-ACKs CRITICAL ALERTs, CRITICAL
ALERT_UPDATEs and ALL_CLEARs, detects duplicates by (Incident_ID, Version),
and sends any line you type to the server.  --drop N ignores the first N
datagrams that need an ack (to watch the server retransmit).
"""
import socket
import sys
import threading

args = [a for a in sys.argv[1:] if not a.startswith("--")]
drop = int(sys.argv[sys.argv.index("--drop") + 1]) if "--drop" in sys.argv else 0
if "--drop" in sys.argv:
    args.remove(str(drop))
name, port = args[0], int(args[1])
server = (args[2] if len(args) > 2 else "127.0.0.1", int(args[3]) if len(args) > 3 else 5000)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", port))
seen = set()


def needs_ack(parts):
    if parts[0] == "ALL_CLEAR":
        return True
    if parts[0] == "ALERT":
        return parts[6] == "CRITICAL"
    if parts[0] == "ALERT_UPDATE":
        return parts[4] == "CRITICAL"
    return False


def listen():
    global drop
    while True:
        data, _ = sock.recvfrom(4096)
        parts = data.decode().split()
        if not parts:
            continue
        if parts[0] in ("ALERT", "ALERT_UPDATE", "ALL_CLEAR"):
            key = (parts[2], parts[3])
            if needs_ack(parts) and drop > 0:
                drop -= 1
                print(f"[{name}] (simulated loss) dropped: {' '.join(parts)}")
                continue
            print(f"[{name}] {'DUPLICATE ' if key in seen else ''}<< {' '.join(parts)}")
            seen.add(key)
            if needs_ack(parts):
                ack = f"ALERT_ACK {parts[1]} {parts[2]} {parts[3]} {name}"
                sock.sendto(ack.encode(), server)
                print(f"[{name}] >> {ack}")
        else:
            print(f"[{name}] << {' '.join(parts)}")


threading.Thread(target=listen, daemon=True).start()
print(f"{name} listening on UDP {port}; type messages to send to {server}")
for line in sys.stdin:
    if line.strip():
        sock.sendto(line.strip().encode(), server)
