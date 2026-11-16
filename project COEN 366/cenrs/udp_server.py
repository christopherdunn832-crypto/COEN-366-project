
import socket

class UDPServer:

    def __init__(self, host, port, database):

        self.db = database

        self.sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM
        )

        self.sock.bind((host, port))

    def start(self):

        print("UDP Server Running...")

        while True:

            data, addr = self.sock.recvfrom(4096)

            msg = data.decode()

            print(f"Received: {msg}")

            self.process(msg, addr)

    def process(self, message, address):

        parts = message.split()

        command = parts[0]

        if command == "REGISTER":

            rq = parts[1]
            name = parts[2]
            role = parts[3]
            ip = parts[4]
            udp_port = parts[5]
            tcp_port = parts[6]

            success = self.db.add_user(
                name,
                role,
                ip,
                udp_port,
                tcp_port
            )

            if success:

                response = (
                    f"REGISTERED {rq} "
                    "[HALL EV JMSB LOYOLA SGW ALL] "
                    "[FIRE SECURITY WEATHER POWER BUILDING GENERAL ALL]"
                )

            else:

                response = (
                    f"REGISTER-DENIED {rq} "
                    "Name_Already_Exists"
                )

            self.sock.sendto(
                response.encode(),
                address
            )