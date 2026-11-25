"""
run_b_standalone.py  -  Run Part B on its own (no A code needed).

Opens the server UDP socket, uses FakeDatabase's hard-coded users, and
routes every datagram to AlertManager.  Use with fake_subscriber.py:

    python run_b_standalone.py                      # server on UDP 5000
    python fake_subscriber.py Alice 5001            # another terminal
    python fake_subscriber.py CampusSecurity 5100   # publisher terminal, then type:
        PUBLISH_ALERT 1 FIRE HALL CRITICAL Fire_Alarm Evacuate_Building NONE
"""
import logging
import socket
import sys

from alert_manager import AlertManager
from fake_db import FakeDatabase

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", PORT))
alerts = AlertManager(FakeDatabase(), send=lambda m, a: sock.sendto(m.encode(), a))
print(f"Part B standalone server on UDP {PORT}")

while True:
    data, addr = sock.recvfrom(4096)
    msg = data.decode(errors="replace")
    logging.info("RECV from %s:%s  %s", addr[0], addr[1], msg)
    reply = alerts.handle(msg, addr) if msg.split()[:1] and msg.split()[0] in AlertManager.COMMANDS else "UNKNOWN_COMMAND"
    if reply:
        logging.info("SEND to %s:%s  %s", addr[0], addr[1], reply)
        sock.sendto(reply.encode(), addr)
