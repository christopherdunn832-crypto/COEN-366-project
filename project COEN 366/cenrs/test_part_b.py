"""
test_part_b.py  -  Automated tests for Part B using real UDP sockets on
localhost and hard-coded fake subscribers (no A code needed).

    python -m unittest test_part_b -v
"""
import socket
import threading
import time
import unittest

from alert_manager import AlertManager
from fake_db import FakeDatabase
from incident import Incident


def udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    s.settimeout(1.0)
    return s


class Harness:
    def __init__(self, timeout=0.3, db=None):
        self.server = udp()
        self.server.settimeout(None)
        self.clients = {n: udp() for n in ("Pub", "Pub2", "Alice", "Bob", "Carol", "Dave")}
        port = lambda n: self.clients[n].getsockname()[1]
        users = {
            "Pub":   {"role": "PUBLISHER",  "ip": "127.0.0.1", "udp_port": port("Pub"),   "tcp_port": 6100},
            "Pub2":  {"role": "PUBLISHER",  "ip": "127.0.0.1", "udp_port": port("Pub2"),  "tcp_port": 6101},
            "Alice": {"role": "SUBSCRIBER", "ip": "127.0.0.1", "udp_port": port("Alice"), "tcp_port": 6001},
            "Bob":   {"role": "SUBSCRIBER", "ip": "127.0.0.1", "udp_port": port("Bob"),   "tcp_port": 6002},
            "Carol": {"role": "BOTH",       "ip": "127.0.0.1", "udp_port": port("Carol"), "tcp_port": 6003},
            "Dave":  {"role": "SUBSCRIBER", "ip": "127.0.0.1", "udp_port": port("Dave"),  "tcp_port": 6004},
        }
        subs = {
            "Alice": [{"zone": "HALL", "type": "FIRE"}],
            "Bob":   [{"zone": "ALL",  "type": "FIRE"}],
            "Carol": [{"zone": "EV",   "type": "ALL"}],
            "Dave":  [{"zone": "HALL", "type": "ALL"}],
        }
        self.db = db or FakeDatabase(users, subs)
        if db:
            db.users, db.subscriptions = users, subs
        self.am = AlertManager(self.db, lambda m, a: self.server.sendto(m.encode(), a),
                               ack_timeout=timeout)
        self.addr = self.server.getsockname()
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                data, addr = self.server.recvfrom(4096)
            except OSError:
                return
            reply = self.am.handle(data.decode(), addr)
            if reply:
                self.server.sendto(reply.encode(), addr)

    def send(self, name, msg):
        self.clients[name].sendto(msg.encode(), self.addr)

    def request(self, name, msg):
        self.send(name, msg)
        return self.recv(name)

    def recv(self, name, timeout=1.0):
        self.clients[name].settimeout(timeout)
        try:
            return self.clients[name].recvfrom(4096)[0].decode()
        except socket.timeout:
            return None

    def drain(self, name, wait=0.3):
        out = []
        while True:
            m = self.recv(name, wait)
            if m is None:
                return out
            out.append(m)

    def ack(self, name, msg):
        p = msg.split()
        self.send(name, f"ALERT_ACK {p[1]} {p[2]} {p[3]} {name}")

    def close(self):
        for t in list(self.am.pending.values()):
            t.timer.cancel()
        self.server.close()
        for c in self.clients.values():
            c.close()


class PartBTests(unittest.TestCase):
    def setUp(self):
        self.h = Harness()

    def tearDown(self):
        self.h.close()

    def publish(self, sev="CRITICAL", cat="FIRE", loc="HALL", att="NONE", who="Pub"):
        r = self.h.request(who, f"PUBLISH_ALERT 45 {cat} {loc} {sev} Fire_Alarm Evacuate_Building {att}")
        self.assertTrue(r.startswith("ALERT_ACCEPTED 45 INC"), r)
        return r.split()[2]

    def test_publish_matching_and_ack(self):
        inc = self.publish()
        a, b, d = self.h.recv("Alice"), self.h.recv("Bob"), self.h.recv("Dave")
        self.assertIsNone(self.h.recv("Carol", 0.4))  # EV/ALL does not match HALL
        for m in (a, b, d):
            self.assertRegex(m, rf"^ALERT \d+ {inc} 1 FIRE HALL CRITICAL Fire_Alarm Evacuate_Building NONE$")
        self.h.ack("Alice", a); self.h.ack("Bob", b); self.h.ack("Dave", d)
        time.sleep(0.2)
        self.assertEqual(self.h.am.get_incident(inc).deliveries["1"],
                         {"Alice": "CONFIRMED", "Bob": "CONFIRMED", "Dave": "CONFIRMED"})
        self.assertEqual(self.h.am.pending, {})
        self.assertEqual(self.h.db.incidents[inc]["status"], "ACTIVE")  # persisted

    def test_retransmit_three_times_then_unconfirmed(self):
        inc = self.publish()
        self.h.ack("Alice", self.h.recv("Alice")); self.h.ack("Dave", self.h.recv("Dave"))
        msgs = self.h.drain("Bob", 0.6)  # Bob never acks
        self.assertEqual(len(msgs), 3, msgs)
        self.assertEqual(len(set(msgs)), 1, "retransmission must be identical (same RQ#)")
        time.sleep(0.5)
        self.assertEqual(self.h.am.get_incident(inc).get_delivery("Bob", 1), "UNCONFIRMED")
        self.assertEqual(self.h.am.get_incident(inc).get_delivery("Alice", 1), "CONFIRMED")

    def test_ack_on_second_attempt_and_duplicate_ack(self):
        inc = self.publish()
        first = self.h.recv("Alice")
        second = self.h.recv("Alice")       # first ack "lost": retransmitted
        self.assertEqual(first, second)
        self.h.ack("Alice", second)
        self.h.ack("Alice", second)         # duplicate ack, must be harmless
        self.assertEqual(self.h.drain("Alice", 0.5), [])
        self.assertEqual(self.h.am.get_incident(inc).get_delivery("Alice"), "CONFIRMED")

    def test_info_needs_no_ack(self):
        inc = self.publish(sev="INFO")
        self.assertIsNotNone(self.h.recv("Alice"))
        self.assertEqual(self.h.drain("Alice", 0.5), [])  # no retransmission
        self.assertEqual(self.h.am.get_incident(inc).get_delivery("Alice"), "SENT")

    def test_publish_denials(self):
        self.assertEqual(self.h.request("Alice", "PUBLISH_ALERT 1 FIRE HALL CRITICAL T D NONE"),
                         "ALERT_DENIED 1 Unauthorized_Role")
        self.assertEqual(self.h.request("Pub", "PUBLISH_ALERT 2 FLOOD HALL CRITICAL T D NONE"),
                         "ALERT_DENIED 2 Invalid_Category")
        self.assertEqual(self.h.request("Pub", "PUBLISH_ALERT 3 FIRE MARS CRITICAL T D NONE"),
                         "ALERT_DENIED 3 Invalid_Location")
        self.assertEqual(self.h.request("Pub", "PUBLISH_ALERT 4 FIRE HALL HUGE T D NONE"),
                         "ALERT_DENIED 4 Invalid_Severity")
        self.assertEqual(self.h.request("Pub", "PUBLISH_ALERT 5 FIRE HALL"),
                         "ALERT_DENIED 5 Malformed_Request")
        stranger = udp()
        stranger.sendto(b"PUBLISH_ALERT 6 FIRE HALL INFO T D NONE", self.h.addr)
        self.assertEqual(stranger.recvfrom(4096)[0].decode(), "ALERT_DENIED 6 Not_Registered")
        stranger.close()

    def test_update_and_close_flow(self):
        inc = self.publish(sev="WARNING")
        for n in ("Alice", "Bob", "Dave"):
            self.h.recv(n)
        self.assertEqual(self.h.request("Pub2", f"UPDATE_ALERT 7 {inc} INFO A B"),
                         "UPDATE_DENIED 7 Not_Incident_Publisher")
        self.assertEqual(self.h.request("Pub", "UPDATE_ALERT 8 INC999 INFO A B"),
                         "UPDATE_DENIED 8 Unknown_Incident")
        self.assertEqual(self.h.request("Pub", f"UPDATE_ALERT 71 {inc} CRITICAL Fire_Spreading Stay_Out"),
                         f"ALERT_UPDATED 71 {inc} 2")
        upd = self.h.recv("Alice")
        self.assertRegex(upd, rf"^ALERT_UPDATE \d+ {inc} 2 CRITICAL Fire_Spreading Stay_Out$")
        self.h.ack("Alice", upd)
        # close: everyone who received it gets ALL_CLEAR, version 3, ack required
        self.assertEqual(self.h.request("Pub", f"CLOSE_ALERT 81 {inc} Building_Reopened"),
                         f"ALERT_CLOSED 81 {inc}")
        msgs = self.h.drain("Alice", 0.5)
        clear = [m for m in msgs if m.startswith("ALL_CLEAR")]
        self.assertRegex(clear[0], rf"^ALL_CLEAR \d+ {inc} 3 Building_Reopened$")
        self.h.ack("Alice", clear[0])
        time.sleep(0.2)
        i = self.h.am.get_incident(inc)
        self.assertEqual((i.status, i.version), ("CLOSED", 3))
        self.assertEqual(i.get_delivery("Alice", 3), "CONFIRMED")
        self.assertEqual(self.h.request("Pub", f"UPDATE_ALERT 9 {inc} INFO A B"),
                         "UPDATE_DENIED 9 Incident_Closed")
        self.assertEqual(self.h.request("Pub", f"CLOSE_ALERT 10 {inc} X"),
                         "CLOSE_DENIED 10 Incident_Closed")

    def test_unacked_old_version_is_superseded(self):
        inc = self.publish()
        self.h.recv("Bob")  # Bob doesn't ack v1
        self.h.request("Pub", f"UPDATE_ALERT 2 {inc} INFO Fire_Out All_Good")
        time.sleep(0.2)
        self.assertEqual(self.h.am.get_incident(inc).get_delivery("Bob", 1), "SUPERSEDED")

    def test_status_report(self):
        inc = self.publish(sev="INFO")
        self.h.drain("Alice")
        self.assertEqual(self.h.request("Alice", f"STATUS_REPORT 91 {inc} Alice SAFE"), "STATUS_RECORDED 91")
        self.assertEqual(self.h.request("Alice", f"STATUS_REPORT 92 {inc} Alice NEED_HELP"), "STATUS_RECORDED 92")
        self.assertEqual(self.h.db.status_reports[inc]["Alice"]["status"], "NEED_HELP")
        self.assertEqual(self.h.request("Alice", "STATUS_REPORT 93 INC999 Alice SAFE"),
                         "STATUS_REJECTED 93 Unknown_Incident")
        self.assertEqual(self.h.request("Alice", f"STATUS_REPORT 94 {inc} Nobody SAFE"),
                         "STATUS_REJECTED 94 Not_Registered")
        self.assertEqual(self.h.request("Alice", f"STATUS_REPORT 95 {inc} Alice HAPPY"),
                         "STATUS_REJECTED 95 Invalid_Status")

    def test_lookups_for_sync_and_attachments(self):
        inc = self.publish(sev="INFO", att="evacuation_map.pdf")
        self.assertEqual(self.h.am.attach_lookup(91, inc, "evacuation_map.pdf"),
                         f"ATTACH_INFO 91 {inc} Pub 127.0.0.1 6100 evacuation_map.pdf")
        self.assertEqual(self.h.am.attach_lookup(92, inc, "other.pdf"),
                         f"ATTACH_DENIED 92 {inc} No_Such_Attachment")
        lines = self.h.am.active_alerts_response(22, "Alice").splitlines()
        self.assertEqual(lines[0], "ACTIVE_ALERTS 22 1")
        self.assertEqual(lines[1], f"{inc} 1 FIRE HALL INFO ACTIVE Fire_Alarm Evacuate_Building evacuation_map.pdf")
        self.assertEqual(self.h.am.active_alerts_response(23, "Carol").splitlines(), ["ACTIVE_ALERTS 23 0"])


class RecoveryTest(unittest.TestCase):
    def test_restart_recovers_incidents(self):
        db = FakeDatabase()
        old = Incident("INC007", "FIRE", "HALL", "CRITICAL", "Fire", "Out", "NONE", "Pub")
        old.set_delivery("Alice", "PENDING")
        db.incidents["INC007"] = old.to_dict()
        h = Harness(db=db)
        try:
            self.assertEqual(h.am.get_incident("INC007").get_delivery("Alice"), "UNCONFIRMED")
            r = h.request("Pub", "PUBLISH_ALERT 1 POWER SGW INFO Outage Wait NONE")
            self.assertEqual(r, "ALERT_ACCEPTED 1 INC008")
        finally:
            h.close()


if __name__ == "__main__":
    unittest.main()
