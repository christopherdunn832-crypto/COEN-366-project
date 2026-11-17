import json
import os
import threading


class Database:
    def __init__(self):
        self.lock = threading.Lock()

        self.users = {}
        self.subscriptions = {}
        self.incidents = {}
        self.status_reports = {}

        self.load()

    def load(self):

        os.makedirs("data", exist_ok=True)
        self.users = self._load_file("data/users.json")
        self.subscriptions = self._load_file("data/subscriptions.json")
        self.incidents = self._load_file("data/incidents.json")
        self.status_reports = self._load_file("data/status.json")


    def save(self):

        self._save_file("data/users.json", self.users)
        self._save_file("data/subscriptions.json", self.subscriptions)
        self._save_file("data/incidents.json", self.incidents)
        self._save_file("data/status.json", self.status_reports)

    def _load_file(self, filename):
        if os.path.exists(filename):
            with open(filename, "r") as f:
                return json.load(f)
        return {}

    def _save_file(self, filename, data):
        with open(filename, "w") as f:
            json.dump(data, f, indent=4)

    # --------------------
    # User Management
    # --------------------

    def add_user(self, username, role, ip, udp_port, tcp_port):
        with self.lock:

            if username in self.users:
                return False

            self.users[username] = {
                "role": role,
                "ip": ip,
                "udp_port": udp_port,
                "tcp_port": tcp_port
            }

            self.save()
            return True

    def remove_user(self, username):
        with self.lock:

            if username not in self.users:
                return False

            self.users.pop(username, None)
            self.subscriptions.pop(username, None)
            self.status_reports.pop(username, None)

            self.save()
            return True

    # --------------------
    # Subscriptions
    # --------------------

    def add_subscription(self, username, zone, alert_type):
        with self.lock:

            if username not in self.subscriptions:
                self.subscriptions[username] = []

            subscription = {
                "zone": zone,
                "type": alert_type
            }

            if subscription not in self.subscriptions[username]:
                self.subscriptions[username].append(subscription)

            self.save()

    def remove_subscription(self, username, zone, alert_type):
        with self.lock:

            if username not in self.subscriptions:
                return

            self.subscriptions[username] = [
                s for s in self.subscriptions[username]
                if not (
                    s["zone"] == zone and
                    s["type"] == alert_type
                )
            ]

            self.save()

    # --------------------
    # Incidents
    # --------------------

    def add_incident(self, incident_id, incident_data):
        with self.lock:
            self.incidents[incident_id] = incident_data
            self.save()

    def update_incident(self, incident_id, updates):
        with self.lock:

            if incident_id not in self.incidents:
                return False

            self.incidents[incident_id].update(updates)
            self.save()

            return True

    def close_incident(self, incident_id):
        with self.lock:

            if incident_id not in self.incidents:
                return False

            self.incidents[incident_id]["status"] = "CLOSED"
            self.save()

            return True

    # --------------------
    # Status Reports
    # --------------------

    def update_status(self, username, status):
        with self.lock:
            self.status_reports[username] = status
            self.save()

    # --------------------
    # Recovery Helpers
    # --------------------

    def get_active_incidents(self):
        return {
            incident_id: incident
            for incident_id, incident in self.incidents.items()
            if incident.get("status") != "CLOSED"
        }
    def generate_incident_id(self):

        return f"INC{len(self.incidents) + 1:03d}"
