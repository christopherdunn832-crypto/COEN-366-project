import socket
import threading
import json


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
                args=(client,),
                daemon=True
            ).start()

    def handle_client(self, client):

        try:

            message = client.recv(4096).decode().strip()

            print(f"TCP: {message}")

            parts = message.split()

            if len(parts) == 0:
                return

            command = parts[0]

            # -------------------------
            # GET_ACTIVE_ALERTS
            # -------------------------
            if command == "GET_ACTIVE_ALERTS":

                rq = parts[1]

                active_alerts = self.db.get_active_incidents()

                response = {
                    "type": "ACTIVE_ALERTS",
                    "rq": rq,
                    "count": len(active_alerts),
                    "alerts": active_alerts
                }

                client.send(
                    json.dumps(response).encode()
                )

            # -------------------------
            # ATTACH_REQ
            # -------------------------
            elif command == "ATTACH_REQ":

                incident_id = parts[1]

                if incident_id in self.db.incidents:

                    incident = self.db.incidents[incident_id]

                    response = json.dumps({
                        "status": "OK",
                        "incident": incident
                    })

                else:

                    response = json.dumps({
                        "status": "ERROR",
                        "message": "Incident not found"
                    })

                client.send(response.encode())

            else:

                client.send(
                    b"UNKNOWN_COMMAND"
                )

        except Exception as e:

            print(f"[TCP ERROR] {e}")

            client.send(
                f"ERROR {str(e)}".encode()
            )

        finally:

            client.close()
