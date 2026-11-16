
import socket
import threading

class TCPServer:

    def __init__(self, host, port, database):

        self.db = database

        self.server = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        self.server.bind((host, port))
        self.server.listen(10)

    def start(self):

        print("TCP Server Running...")

        while True:

            client, addr = self.server.accept()

            threading.Thread(
                target=self.handle_client,
                args=(client,)
            ).start()

    def handle_client(self, client):

        message = client.recv(4096).decode()

        print("TCP:", message)

        parts = message.split()

        if parts[0] == "GET_ACTIVE_ALERTS":

            rq = parts[1]

            response = (
                f"ACTIVE_ALERTS {rq} "
                f"{len(self.db.incidents)}"
            )

            client.send(
                response.encode()
            )

        client.close()