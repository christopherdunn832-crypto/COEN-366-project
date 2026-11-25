"""Section 2.9: UDP discovery and direct TCP attachment transfer."""
import socket
import threading
import tempfile
import os
import zlib
from pathlib import Path
from urllib.parse import quote, unquote

TIMEOUT = 10
CHUNK = 65536


def encode_name(name):
    if not name or name in ('.', '..', 'NONE') or any(c in name for c in '/\\\x00\r\n'):
        raise ValueError('Invalid filename')
    return quote(name, safe='')


def discover(db, parts, address):
    rq = parts[1] if len(parts) > 1 else '0'
    iid = parts[2] if len(parts) > 2 else 'UNKNOWN'
    def deny(reason):
        return f'ATTACH_DENIED {rq} {iid} {reason}'
    if len(parts) != 4:
        return deny('Malformed_Request')
    with db.lock:
        if not any((u['ip'], u['udp_port']) == address and u['role'] in ('SUBSCRIBER', 'BOTH') for u in db.users.values()):
            return deny('Unauthorized_Requester')
        incident = db.incidents.get(iid)
        if not incident or incident.get('status') != 'ACTIVE':
            return deny('Incident_Not_Active')
        if parts[3] == 'NONE' or incident.get('attachment') != parts[3]:
            return deny('Attachment_Mismatch')
        publisher = incident.get('publisher')
        peer = db.users.get(publisher)
        if not peer or peer['role'] not in ('PUBLISHER', 'BOTH'):
            return deny('Publisher_Unavailable')
        return f"ATTACH_INFO {rq} {iid} {publisher} {peer['ip']} {peer['tcp_port']} {parts[3]}"


def send_line(sock, message):
    print('Sending TCP:', message, flush=True)
    sock.sendall((message + '\n').encode())


def read_line(stream):
    line = stream.readline(8193)
    if not line.endswith(b'\n') or len(line) > 8192:
        raise ValueError('Incomplete_or_invalid_header')
    message = line.decode().strip()
    print('Received TCP:', message, flush=True)
    return message.split()


class PeerServer:
    def __init__(self, port):
        self.files = {}
        self.lock = threading.Lock()
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('0.0.0.0', port))
        self.sock.listen()
        self.sock.settimeout(0.5)
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self.listen, daemon=True)
        self.thread.start()

    def offer(self, iid, path):
        path = Path(path).resolve(strict=True)
        if not path.is_file():
            raise ValueError('Not a file')
        with self.lock:
            self.files[iid, encode_name(path.name)] = path

    def close(self):
        self.stopped.set()
        self.thread.join()
        self.sock.close()

    def listen(self):
        while not self.stopped.is_set():
            try:
                conn, _ = self.sock.accept()
            except TimeoutError:
                continue
            threading.Thread(target=self.serve, args=(conn,), daemon=True).start()

    def serve(self, conn):
        with conn:
            conn.settimeout(TIMEOUT)
            rq, iid, name = '0', 'UNKNOWN', 'UNKNOWN'
            started = False
            try:
                with conn.makefile('rb') as stream:
                    parts = read_line(stream)
                    if len(parts) != 5 or parts[0] != 'GET_ATTACHMENT':
                        raise ValueError('Malformed_Request')
                    _, rq, _, iid, name = parts
                    with self.lock:
                        path = self.files.get((iid, name))
                    if path is None:
                        raise ValueError('Unknown_Attachment')
                    # Snapshot to disk so checksum and transmitted bytes match even if source changes.
                    with path.open('rb') as source, tempfile.TemporaryFile() as snapshot:
                        size = crc = 0
                        while chunk := source.read(CHUNK):
                            snapshot.write(chunk)
                            size += len(chunk)
                            crc = zlib.crc32(chunk, crc)
                        snapshot.seek(0)
                        send_line(conn, f'ATTACH_DATA {rq} {iid} {name} {size} {crc:08X}')
                        started = True
                        while chunk := snapshot.read(CHUNK):
                            conn.sendall(chunk)
                    reply = read_line(stream)
                    if reply != ['ATTACH_OK', rq, iid, name]:
                        print('Transfer not confirmed:', reply)
                    else:
                        print(f'Transfer confirmed: {size} bytes')
            except (OSError, ValueError) as exc:
                print('Publisher transfer failed:', exc)
                if not started:
                    try:
                        send_line(conn, f'ATTACH_ERROR {rq} {iid} {name} File_Unavailable' if isinstance(exc, OSError) else f'ATTACH_ERROR {rq} {iid} {name} {exc}')
                    except OSError:
                        pass


def download(endpoint, rq, subscriber, iid, name, directory):
    decoded = unquote(name)
    if encode_name(decoded) != name:
        raise ValueError('Invalid filename encoding')
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / decoded
    temp = None
    with socket.create_connection(endpoint, timeout=TIMEOUT) as conn:
        with conn.makefile('rb') as stream:
            send_line(conn, f'GET_ATTACHMENT {rq} {subscriber} {iid} {name}')
            header = read_line(stream)
            if header[:1] == ['ATTACH_ERROR']:
                raise ValueError(' '.join(header))
            try:
                if len(header) != 6 or header[:4] != ['ATTACH_DATA', rq, iid, name]:
                    raise ValueError('Invalid_Header')
                size = int(header[4])
                if size < 0 or len(header[5]) != 8:
                    raise ValueError('Invalid_Header')
                expected = int(header[5], 16)
                remaining, crc = size, 0
                with tempfile.NamedTemporaryFile(dir=directory, delete=False) as output:
                    temp = output.name
                    while remaining:
                        chunk = stream.read(min(CHUNK, remaining))
                        if not chunk:
                            raise ValueError('Incomplete_Transfer')
                        output.write(chunk)
                        remaining -= len(chunk)
                        crc = zlib.crc32(chunk, crc)
                if crc != expected:
                    raise ValueError('Checksum_Mismatch')
                os.replace(temp, target)
                temp = None
            except (OSError, ValueError) as exc:
                try:
                    send_line(conn, f'ATTACH_ERROR {rq} {iid} {name} ' + ('Transfer_IO_Error' if isinstance(exc, OSError) else str(exc).replace(' ', '_')))
                except OSError:
                    pass
                raise
            finally:
                if temp is not None:
                    os.unlink(temp)
            send_line(conn, f'ATTACH_OK {rq} {iid} {name}')
            print(f'Downloaded {size} bytes to {target}')
    return target
