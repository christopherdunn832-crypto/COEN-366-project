
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

    try:
        parts = message.split()

        if len(parts) == 0:
            return

        command = parts[0]

        # -------------------------
        # REGISTER
        # -------------------------
        if command == "REGISTER":

            rq = parts[1]
            name = parts[2]
            role = parts[3]
            ip = parts[4]
            udp_port = int(parts[5])
            tcp_port = int(parts[6])

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

        # -------------------------
        # DE-REGISTER
        # -------------------------
        elif command == "DE-REGISTER":

            rq = parts[1]
            username = parts[2]

            success = self.db.remove_user(username)

            if success:
                response = f"DE-REGISTERED {rq}"
            else:
                response = f"DE-REGISTER-DENIED {rq}"

        # -------------------------
        # SUBSCRIBE
        # -------------------------
        elif command == "SUBSCRIBE":

            rq = parts[1]
            username = parts[2]
            zone = parts[3]
            alert_type = parts[4]

            self.db.add_subscription(
                username,
                zone,
                alert_type
            )

            response = f"SUBSCRIBED {rq}"

        # -------------------------
        # UNSUBSCRIBE
        # -------------------------
        elif command == "UNSUBSCRIBE":

            rq = parts[1]
            username = parts[2]
            zone = parts[3]
            alert_type = parts[4]

            self.db.remove_subscription(
                username,
                zone,
                alert_type
            )

            response = f"UNSUBSCRIBED {rq}"

        # -------------------------
        # STATUS_REPORT
        # -------------------------
        elif command == "STATUS_REPORT":

            rq = parts[1]
            username = parts[2]
            status = parts[3]

            self.db.update_status(
                username,
                status
            )

            response = f"STATUS_RECEIVED {rq}"

        # -------------------------
        # UNKNOWN COMMAND
        # -------------------------
        else:
            response = "UNKNOWN_COMMAND"

        self.sock.sendto(
            response.encode(),
            address
        )

    except Exception as e:

        error_message = f"ERROR {str(e)}"

        self.sock.sendto(
            error_message.encode(),
            address
        )

        print(f"[UDP ERROR] {e}")
            )
