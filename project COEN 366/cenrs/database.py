import json
import os

class Database:
    def __init__(self):
        self.users = {}
        self.subscriptions = {}
        self.incidents = {}
        self.status_reports = {}

    def add_user(self, name, role, ip, udp_port, tcp_port):

        if name in self.users:
            return False

        self.users[name] = {
            "role": role,
            "ip": ip,
            "udp_port": udp_port,
            "tcp_port": tcp_port
        }

        return True

    def remove_user(self, name):

        if name in self.users:
            del self.users[name]

    def save(self):

        with open("data/users.json", "w") as f:
            json.dump(self.users, f, indent=4)

    def load(self):

        if os.path.exists("data/users.json"):
            with open("data/users.json") as f:
                self.users = json.load(f)