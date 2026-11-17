from udp_server import start_udp_server
from tcp_server import start_tcp_server
import threading

udp_thread = threading.Thread(
    target=start_udp_server,
    daemon=True
)

tcp_thread = threading.Thread(
    target=start_tcp_server,
    daemon=True
)

udp_thread.start()
tcp_thread.start()

print("CENRS Server Running")

udp_thread.join()
tcp_thread.join()
