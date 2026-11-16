# server.py

from database import Database
from udp_server import UDPServer
from tcp_server import TCPServer

import threading

db = Database()
db.load()

udp_server = UDPServer(
    "0.0.0.0",
    5000,
    db
)

tcp_server = TCPServer(
    "0.0.0.0",
    6000,
    db
)

threading.Thread(
    target=udp_server.start
).start()

threading.Thread(
    target=tcp_server.start
).start()

print("CENRS Server Started")
