from database import Database
import socket

# Load saved data on startup
db = Database()

HOST = "0.0.0.0"
PORT = 5000

server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind((HOST, PORT))

print(f"Server listening on {HOST}:{PORT}")

while True:

    data, addr = server.recvfrom(4096)
    message = data.decode().strip()

    print(f"Received: {message}")

    parts = message.split()

    try:

        command = parts[0]

        # REGISTER rq username role ip udp_port tcp_port
        if command == "REGISTER":

            rq = parts[1]
            username = parts[2]
            role = parts[3]
            ip = parts[4]
            udp_port = int(parts[5])
            tcp_port = int(parts[6])

            db.add_user(
                username,
                role,
                ip,
                udp_port,
                tcp_port
            )

            response = f"REGISTERED {rq}"

            server.sendto(response.encode(), addr)

        # DE-REGISTER rq username
        elif command == "DE-REGISTER":

            rq = parts[1]
            username = parts[2]

            db.remove_user(username)

            response = f"DE-REGISTERED {rq}"

            server.sendto(response.encode(), addr)

        # SUBSCRIBE rq username zone type
        elif command == "SUBSCRIBE":

            rq = parts[1]
            username = parts[2]
            zone = parts[3]
            alert_type = parts[4]

            db.add_subscription(
                username,
                zone,
                alert_type
            )

            response = f"SUBSCRIBED {rq}"

            server.sendto(response.encode(), addr)

        # UNSUBSCRIBE rq username zone type
        elif command == "UNSUBSCRIBE":

            rq = parts[1]
            username = parts[2]
            zone = parts[3]
            alert_type = parts[4]

            db.remove_subscription(
                username,
                zone,
                alert_type
            )

            response = f"UNSUBSCRIBED {rq}"

            server.sendto(response.encode(), addr)

        # STATUS_REPORT rq username status
        elif command == "STATUS_REPORT":

            rq = parts[1]
            username = parts[2]
            status = parts[3]

            db.update_status(
                username,
                status
            )

            response = f"STATUS_RECEIVED {rq}"

            server.sendto(response.encode(), addr)

        else:

            response = "UNKNOWN_COMMAND"
            server.sendto(response.encode(), addr)

    except Exception as e:

        print("Error:", e)

        server.sendto(
            f"ERROR {str(e)}".encode(),
            addr
        )
