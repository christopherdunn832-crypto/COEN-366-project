"""
fake_db.py  -  Stand-in for A's Database while A's part is not running.

Same attributes / methods that AlertManager uses from A's Database, kept in
memory, pre-loaded with a few hard-coded fake users and subscriptions.
Swap it for A's Database (database.py) when integrating - nothing else changes.
"""
import threading


class FakeDatabase:
    def __init__(self, users=None, subscriptions=None):
        self.lock = threading.Lock()
        self.users = users if users is not None else {
            "CampusSecurity": {"role": "PUBLISHER",  "ip": "127.0.0.1", "udp_port": 5100, "tcp_port": 6100},
            "Alice":          {"role": "SUBSCRIBER", "ip": "127.0.0.1", "udp_port": 5001, "tcp_port": 6001},
            "Bob":            {"role": "SUBSCRIBER", "ip": "127.0.0.1", "udp_port": 5002, "tcp_port": 6002},
            "Carol":          {"role": "BOTH",       "ip": "127.0.0.1", "udp_port": 5003, "tcp_port": 6003},
        }
        self.subscriptions = subscriptions if subscriptions is not None else {
            "Alice": [{"zone": "HALL", "type": "FIRE"}],
            "Bob":   [{"zone": "ALL",  "type": "FIRE"}],
            "Carol": [{"zone": "EV",   "type": "ALL"}],
        }
        self.incidents = {}
        self.status_reports = {}
        self.saves = 0

    def save(self):
        self.saves += 1          # nothing written to disk

    def add_incident(self, incident_id, incident_data):
        with self.lock:
            self.incidents[incident_id] = incident_data
            self.save()
