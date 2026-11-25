import argparse
import json
import socket
import threading
from itertools import count
from queue import Empty, Queue
from time import monotonic

SOCKET_TIMEOUT = 3.0
BUFFER_SIZE = 65535
ROLES = ("SUBSCRIBER", "PUBLISHER", "BOTH")
REPLIES = {
    "REGISTER": {"REGISTERED", "REGISTER-DENIED"},
    "DE-REGISTER": {"DE-REGISTERED", "DE-REGISTER-DENIED"},
    "SUBSCRIBE": {"SUBSCRIBED", "SUBSCRIPTION-DENIED"},
    "UNSUBSCRIBE": {"UNSUBSCRIBED", "UNSUBSCRIPTION-DENIED", "SUBSCRIPTION-DENIED"},
}


def receive_udp(sock, replies, stopped):
    while not stopped.is_set():
        try:
            message = sock.recv(BUFFER_SIZE).decode("utf-8")
        except TimeoutError:
            continue
        except UnicodeError:
            print("\nReceived invalid UTF-8 from the UDP server.")
            continue
        except OSError as error:
            print(f"UDP receive failed: {error}")
            return

        print(f"\nReceived UDP: {message}")
        parts = message.split()
        if parts and (parts[0] == "UNKNOWN_COMMAND" or parts[0] == "ERROR"):
            replies.put(parts)
        elif len(parts) >= 2 and any(parts[0] in codes for codes in REPLIES.values()):
            replies.put(parts)


def send_request(sock, replies, command, request_id, *fields):
    message = " ".join((command, request_id, *fields))
    print(f"Sending UDP: {message}")
    sock.send(message.encode("utf-8"))

    # One command is in flight at a time. Skip late replies to earlier commands.
    deadline = monotonic() + SOCKET_TIMEOUT
    while (remaining := deadline - monotonic()) > 0:
        try:
            parts = replies.get(timeout=remaining)
        except Empty:
            break
        if parts[0] in {"ERROR", "UNKNOWN_COMMAND"}:
            return parts[0]
        if parts[0] in REPLIES[command] and parts[1] == request_id:
            return parts[0]
    raise TimeoutError(f"No reply to {command} {request_id} within {SOCKET_TIMEOUT:g} seconds.")


def sync_active_alerts(server_address, request_id, name):
    message = f"GET_ACTIVE_ALERTS {request_id} {name}"
    with socket.create_connection(server_address, timeout=SOCKET_TIMEOUT) as sock:
        print(f"Sending TCP: {message}")
        sock.sendall(message.encode("utf-8"))
        # The current server sends one JSON response and closes the connection.
        chunks = []
        while chunk := sock.recv(4096):
            chunks.append(chunk)

    reply = json.loads(b"".join(chunks))
    if not isinstance(reply, dict) or reply.get("type") != "ACTIVE_ALERTS":
        raise ValueError("Expected an ACTIVE_ALERTS response.")
    alerts = reply.get("alerts")
    if (
        reply.get("rq") != request_id
        or not isinstance(alerts, (dict, list))
        or reply.get("count") != len(alerts)
    ):
        raise ValueError("Invalid ACTIVE_ALERTS request number or record count.")

    print(f"Received TCP: ACTIVE_ALERTS {request_id} {len(alerts)}")
    if isinstance(alerts, dict):
        for incident_id, alert in alerts.items():
            print(f"{incident_id} {json.dumps(alert, ensure_ascii=False)}")
    else:
        for alert in alerts:
            print(json.dumps(alert, ensure_ascii=False))


def run_client(args):
    request_ids = count(1)
    replies = Queue()
    stopped = threading.Event()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.5)
        sock.connect((args.host, args.udp_port))
        client_ip, client_udp_port = sock.getsockname()
        receiver = threading.Thread(target=receive_udp, args=(sock, replies, stopped))
        receiver.start()
        registered = False
        try:
            result = send_request(
                sock, replies, "REGISTER", str(next(request_ids)),
                args.name, args.role, client_ip, str(client_udp_port), str(args.peer_port),
            )
            registered = result == "REGISTERED"
            if not registered:
                return
            print("Commands: subscribe LOCATION CATEGORY, unsubscribe LOCATION CATEGORY, sync, quit")
            while True:
                parts = input("> ").split()
                if not parts:
                    continue
                command = parts[0].lower()
                if command == "quit" and len(parts) == 1:
                    break
                try:
                    if command in {"subscribe", "unsubscribe"} and len(parts) == 3:
                        location, category = (part.upper() for part in parts[1:])
                        send_request(
                            sock, replies, command.upper(), str(next(request_ids)),
                            args.name, location, category,
                        )
                    elif command == "sync" and len(parts) == 1:
                        sync_active_alerts((args.host, args.tcp_port), str(next(request_ids)), args.name)
                    else:
                        print("Enter subscribe LOCATION CATEGORY, unsubscribe LOCATION CATEGORY, sync, or quit.")
                except (OSError, ValueError) as error:
                    print(f"Request failed: {error}")
        except (EOFError, KeyboardInterrupt):
            print()
        finally:
            try:
                if registered:
                    send_request(sock, replies, "DE-REGISTER", str(next(request_ids)), args.name)
            finally:
                stopped.set()
                receiver.join()


def main():
    parser = argparse.ArgumentParser(description="CENRS command-line client")
    parser.add_argument("name", help="unique name without spaces")
    parser.add_argument("--role", choices=ROLES, default="SUBSCRIBER")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--udp-port", type=int, required=True, help="server UDP port")
    parser.add_argument("--tcp-port", type=int, required=True, help="server TCP sync port")
    parser.add_argument("--peer-port", type=int, required=True, help="advertised peer TCP port")
    args = parser.parse_args()
    if not args.name or any(char.isspace() for char in args.name):
        parser.error("name must be a single word")
    if any(not 1 <= port <= 65535 for port in (args.udp_port, args.tcp_port, args.peer_port)):
        parser.error("ports must be between 1 and 65535")
    try:
        run_client(args)
    except OSError as error:
        parser.exit(1, f"Client error: {error}\n")


if __name__ == "__main__":
    main()
