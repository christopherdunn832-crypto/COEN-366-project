"""
alert_manager.py  -  Part B: incident / alert handling on the CENRS server.

Handles these UDP messages (spec sections 2.3 - 2.8):

    PUBLISH_ALERT  RQ# Category Location Severity Title Description Attachment
    UPDATE_ALERT   RQ# Incident_ID Severity Title Description
    CLOSE_ALERT    RQ# Incident_ID Reason
    ALERT_ACK      RQ# Incident_ID Version Name
    STATUS_REPORT  RQ# Incident_ID Name Status

and sends these to subscribers:

    ALERT, ALERT_UPDATE, ALL_CLEAR   (with ack + retransmission when required)

It does NOT own a socket.  A's UDP server passes every datagram whose command
is in AlertManager.COMMANDS to handle(), and gives us a send(msg, addr)
function that writes on A's UDP socket.  ALERT_ACKs therefore arrive on the
same server port the alerts were sent from.

Database it expects (A's Database class already has all of this):
    db.lock            threading.Lock
    db.users           {name: {"role", "ip", "udp_port", "tcp_port"}}
    db.subscriptions   {name: [{"zone": LOCATION, "type": CATEGORY}, ...]}
    db.incidents       {incident_id: Incident.to_dict()}
    db.status_reports  dict (we store {incident_id: {name: {...}}} in it)
    db.add_incident(incident_id, dict)   insert-or-replace + save
    db.save()
"""

import itertools
import logging
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple

from incident import (
    Incident, LOCATIONS, CATEGORIES, SEVERITIES, USER_STATUSES,
    PUBLISHER_ROLES, SUBSCRIBER_ROLES, ACTIVE, CLOSED,
    SENT, PENDING, CONFIRMED, UNCONFIRMED, SUPERSEDED,
    decode_text,
)

log = logging.getLogger("cenrs.alerts")

Address = Tuple[str, int]


class _Pending:
    """One outgoing message waiting for an ALERT_ACK."""

    def __init__(self, rq, name, incident_id, version, message, addr):
        self.rq = rq
        self.name = name
        self.incident_id = incident_id
        self.version = version
        self.message = message
        self.addr = addr
        self.attempts = 1
        self.timer: Optional[threading.Timer] = None


class AlertManager:
    COMMANDS = {"PUBLISH_ALERT", "UPDATE_ALERT", "CLOSE_ALERT",
                "ALERT_ACK", "STATUS_REPORT"}

    def __init__(self, db, send: Callable[[str, Address], None],
                 ack_timeout: float = 2.0, max_attempts: int = 3):
        self.db = db
        self._send_raw = send
        self.ack_timeout = ack_timeout
        self.max_attempts = max_attempts

        self.lock = threading.RLock()
        self.incidents: Dict[str, Incident] = {}
        self.pending: Dict[int, _Pending] = {}       # outgoing RQ# -> pending
        self._rq_counter = itertools.count(1)

        self._recover()

    # ======================================================================
    # Entry point called by A's UDP server
    # ======================================================================
    def handle(self, message: str, address: Address) -> Optional[str]:
        """Process one datagram. Returns the reply to send back to `address`,
        or None when no reply is due (ALERT_ACK)."""
        parts = message.strip().split()
        if not parts:
            return None
        command = parts[0]
        try:
            if command == "PUBLISH_ALERT":
                return self._publish(parts, address)
            if command == "UPDATE_ALERT":
                return self._update(parts, address)
            if command == "CLOSE_ALERT":
                return self._close(parts, address)
            if command == "ALERT_ACK":
                self._ack(parts, address)
                return None
            if command == "STATUS_REPORT":
                return self._status_report(parts, address)
        except Exception:  # never let one bad datagram kill the server
            log.exception("Error handling %r from %s", message, address)
            rq = parts[1] if len(parts) > 1 else "0"
            return f"ERROR {rq} Internal_Server_Error"
        return None

    # ======================================================================
    # 2.3 PUBLISH_ALERT
    # ======================================================================
    def _publish(self, parts, address):
        # PUBLISH_ALERT RQ# Category Location Severity Title Description Attachment
        rq = parts[1] if len(parts) > 1 else "0"
        if len(parts) != 8:
            return self._deny("ALERT_DENIED", rq, "Malformed_Request")
        _, rq, category, location, severity, title, description, attachment = parts

        publisher = self._user_by_address(address)
        if publisher is None:
            return self._deny("ALERT_DENIED", rq, "Not_Registered")
        name, user = publisher
        if user.get("role") not in PUBLISHER_ROLES:
            return self._deny("ALERT_DENIED", rq, "Unauthorized_Role")
        if category not in CATEGORIES:
            return self._deny("ALERT_DENIED", rq, "Invalid_Category")
        if location not in LOCATIONS:
            return self._deny("ALERT_DENIED", rq, "Invalid_Location")
        if severity not in SEVERITIES:
            return self._deny("ALERT_DENIED", rq, "Invalid_Severity")

        with self.lock:
            incident = Incident(
                incident_id=self._next_incident_id(),
                category=category, location=location, severity=severity,
                title=decode_text(title), description=decode_text(description),
                attachment=attachment, publisher=name,
            )
            self.incidents[incident.incident_id] = incident
            self._persist(incident)

        log.info("Incident %s created by %s: %s %s %s", incident.incident_id,
                 name, category, location, severity)
        # Reply first, then distribute in the background so the publisher
        # is not kept waiting and the UDP loop is not blocked.
        self._in_background(self._distribute_new, incident.incident_id)
        return f"ALERT_ACCEPTED {rq} {incident.incident_id}"

    # ======================================================================
    # 2.6 UPDATE_ALERT
    # ======================================================================
    def _update(self, parts, address):
        # UPDATE_ALERT RQ# Incident_ID Severity Title Description
        rq = parts[1] if len(parts) > 1 else "0"
        if len(parts) != 6:
            return self._deny("UPDATE_DENIED", rq, "Malformed_Request")
        _, rq, incident_id, severity, title, description = parts

        if severity not in SEVERITIES:
            return self._deny("UPDATE_DENIED", rq, "Invalid_Severity")
        with self.lock:
            incident, reason = self._check_owner(incident_id, address)
            if reason:
                return self._deny("UPDATE_DENIED", rq, reason)
            incident.severity = severity
            incident.title = decode_text(title)
            incident.description = decode_text(description)
            incident.version += 1
            incident.updated_at = time.time()
            self._persist(incident)
            version = incident.version

        log.info("Incident %s updated to version %d (%s)", incident_id, version, severity)
        self._in_background(self._distribute_update, incident_id)
        return f"ALERT_UPDATED {rq} {incident_id} {version}"

    # ======================================================================
    # 2.7 CLOSE_ALERT
    # ======================================================================
    def _close(self, parts, address):
        # CLOSE_ALERT RQ# Incident_ID Reason
        rq = parts[1] if len(parts) > 1 else "0"
        if len(parts) != 4:
            return self._deny("CLOSE_DENIED", rq, "Malformed_Request")
        _, rq, incident_id, reason_text = parts

        with self.lock:
            incident, reason = self._check_owner(incident_id, address)
            if reason:
                return self._deny("CLOSE_DENIED", rq, reason)
            incident.status = CLOSED
            incident.close_reason = decode_text(reason_text)
            incident.version += 1
            incident.updated_at = time.time()
            self._persist(incident)

        log.info("Incident %s closed (version %d): %s", incident_id,
                 incident.version, incident.close_reason)
        self._in_background(self._distribute_all_clear, incident_id)
        return f"ALERT_CLOSED {rq} {incident_id}"

    # ======================================================================
    # 2.5 ALERT_ACK
    # ======================================================================
    def _ack(self, parts, address):
        # ALERT_ACK RQ# Incident_ID Version Name
        if len(parts) != 5 or not parts[1].isdigit() or not parts[3].isdigit():
            log.warning("Malformed ALERT_ACK from %s: %s", address, " ".join(parts))
            return
        rq, incident_id, version, name = int(parts[1]), parts[2], int(parts[3]), parts[4]

        with self.lock:
            p = self.pending.get(rq)
            if p is None:
                # Already acked, already gave up, or bogus.  Spec: duplicate
                # ALERT_ACK must be tolerated -> just log it.
                incident = self.incidents.get(incident_id)
                state = incident.get_delivery(name, version) if incident else None
                log.info("Duplicate/late ALERT_ACK rq=%d %s v%d from %s (state=%s)",
                         rq, incident_id, version, name, state)
                if incident and state in (UNCONFIRMED, PENDING):
                    # late ack after giving up: still worth recording
                    incident.set_delivery(name, CONFIRMED, version)
                    self._persist(incident)
                return
            if (p.incident_id, p.version, p.name) != (incident_id, version, name):
                log.warning("ALERT_ACK rq=%d does not match what was sent "
                            "(%s v%d to %s) - ignored", rq, p.incident_id,
                            p.version, p.name)
                return
            if p.timer:
                p.timer.cancel()
            del self.pending[rq]
            incident = self.incidents[incident_id]
            incident.set_delivery(name, CONFIRMED, version)
            self._persist(incident)
        log.info("ALERT_ACK rq=%d: %s confirmed %s v%d (attempt %d)",
                 rq, name, incident_id, version, p.attempts)

    # ======================================================================
    # 2.8 STATUS_REPORT
    # ======================================================================
    def _status_report(self, parts, address):
        # STATUS_REPORT RQ# Incident_ID Name Status
        rq = parts[1] if len(parts) > 1 else "0"
        if len(parts) != 5:
            return self._deny("STATUS_REJECTED", rq, "Malformed_Request")
        _, rq, incident_id, name, status = parts

        if name not in self._users_snapshot():
            return self._deny("STATUS_REJECTED", rq, "Not_Registered")
        if status not in USER_STATUSES:
            return self._deny("STATUS_REJECTED", rq, "Invalid_Status")
        with self.lock:
            incident = self.incidents.get(incident_id)
            if incident is None:
                return self._deny("STATUS_REJECTED", rq, "Unknown_Incident")
            if not incident.is_active:
                return self._deny("STATUS_REJECTED", rq, "Incident_Closed")

        # Latest status per (incident, user), as the spec requires.
        with self.db.lock:
            self.db.status_reports.setdefault(incident_id, {})[name] = {
                "status": status, "time": time.time()}
            self.db.save()
        log.info("STATUS_REPORT %s: %s is %s", incident_id, name, status)
        return f"STATUS_RECORDED {rq}"

    # ======================================================================
    # Distribution
    # ======================================================================
    def _distribute_new(self, incident_id):
        with self.lock:
            incident = self.incidents[incident_id]
            targets = self._matching_subscribers(incident)
            need_ack = incident.severity == "CRITICAL"
            for name, addr in targets:
                self._send_to(incident, name, addr, incident.alert_message, need_ack)
            self._persist(incident)
        log.info("ALERT %s v%d sent to %d subscriber(s)%s", incident_id,
                 incident.version, len(targets), " (ack required)" if need_ack else "")

    def _distribute_update(self, incident_id):
        with self.lock:
            incident = self.incidents[incident_id]
            need_ack = incident.severity == "CRITICAL"
            targets = self._matching_subscribers(incident, include_previous=True)
            for name, addr in targets:
                # Someone who never saw the incident gets a full ALERT with the
                # current state; previous recipients get ALERT_UPDATE.
                builder = (incident.update_message if name in incident.recipients
                           else incident.alert_message)
                self._send_to(incident, name, addr, builder, need_ack)
            self._persist(incident)
        log.info("ALERT_UPDATE %s v%d sent to %d subscriber(s)", incident_id,
                 incident.version, len(targets))

    def _distribute_all_clear(self, incident_id):
        with self.lock:
            incident = self.incidents[incident_id]
            # "subscribers that received or currently match the incident"
            targets = self._matching_subscribers(incident, include_previous=True)
            for name, addr in targets:
                self._send_to(incident, name, addr, incident.all_clear_message, True)
            self._persist(incident)
        log.info("ALL_CLEAR %s v%d sent to %d subscriber(s)", incident_id,
                 incident.version, len(targets))

    def _send_to(self, incident, name, addr, builder, need_ack):
        """Send one message to one subscriber. Caller holds self.lock."""
        self._supersede_older(incident.incident_id, name, incident.version)
        rq = next(self._rq_counter)
        message = builder(rq)
        self._send(message, addr)
        if name not in incident.recipients:
            incident.recipients.append(name)
        if need_ack:
            p = _Pending(rq, name, incident.incident_id, incident.version, message, addr)
            self.pending[rq] = p
            self._start_timer(p)
            incident.set_delivery(name, PENDING)
        else:
            incident.set_delivery(name, SENT)

    # ---------------- 2.5 timers / retransmission ----------------
    def _start_timer(self, p: _Pending):
        p.timer = threading.Timer(self.ack_timeout, self._on_timeout, args=(p.rq,))
        p.timer.daemon = True
        p.timer.start()

    def _on_timeout(self, rq):
        with self.lock:
            p = self.pending.get(rq)
            if p is None:
                return                      # acked meanwhile
            if p.attempts >= self.max_attempts:
                del self.pending[rq]
                incident = self.incidents.get(p.incident_id)
                if incident:
                    incident.set_delivery(p.name, UNCONFIRMED, p.version)
                    self._persist(incident)
                log.warning("No ALERT_ACK from %s for %s v%d after %d attempts "
                            "-> UNCONFIRMED", p.name, p.incident_id, p.version, p.attempts)
                return
            p.attempts += 1
            log.info("Timeout rq=%d, retransmitting to %s (attempt %d/%d)",
                     rq, p.name, p.attempts, self.max_attempts)
            self._send(p.message, p.addr)   # same message, same RQ#
            self._start_timer(p)

    def _supersede_older(self, incident_id, name, new_version):
        """A newer version replaces any older one still being retried."""
        for rq, p in list(self.pending.items()):
            if p.incident_id == incident_id and p.name == name and p.version < new_version:
                if p.timer:
                    p.timer.cancel()
                del self.pending[rq]
                self.incidents[incident_id].set_delivery(name, SUPERSEDED, p.version)
                log.info("rq=%d (%s v%d to %s) superseded by v%d",
                         rq, incident_id, p.version, name, new_version)

    # ======================================================================
    # Lookups other parts can use
    # ======================================================================
    def get_incident(self, incident_id) -> Optional[Incident]:
        with self.lock:
            return self.incidents.get(incident_id)

    def active_incidents_for(self, name) -> List[Incident]:
        """Active incidents matching `name`'s subscriptions (for GET_ACTIVE_ALERTS)."""
        subs = self._subscriptions_snapshot().get(name, [])
        with self.lock:
            return [i for i in self.incidents.values()
                    if i.is_active and any(i.matches(s["zone"], s["type"]) for s in subs)]

    def active_alerts_response(self, rq, name) -> str:
        """Full TCP reply for GET_ACTIVE_ALERTS RQ# Name (spec 2.10):
        header line, then one Incident.to_record() line per incident."""
        if name not in self._users_snapshot():
            return f"ACTIVE_ALERTS {rq} 0\n"
        records = self.active_incidents_for(name)
        lines = [f"ACTIVE_ALERTS {rq} {len(records)}"] + [i.to_record() for i in records]
        return "\n".join(lines) + "\n"

    def attach_lookup(self, rq, incident_id, file_name) -> str:
        """Reply for ATTACH_REQ RQ# Incident_ID File_Name (spec 2.9 A), for D."""
        with self.lock:
            incident = self.incidents.get(incident_id)
            if incident is None:
                return f"ATTACH_DENIED {rq} {incident_id} Unknown_Incident"
            if not incident.is_active:
                return f"ATTACH_DENIED {rq} {incident_id} Incident_Closed"
            if not incident.has_attachment() or incident.attachment != file_name:
                return f"ATTACH_DENIED {rq} {incident_id} No_Such_Attachment"
            publisher = incident.publisher
        user = self._users_snapshot().get(publisher)
        if user is None:
            return f"ATTACH_DENIED {rq} {incident_id} Publisher_Unavailable"
        return (f"ATTACH_INFO {rq} {incident_id} {publisher} {user['ip']} "
                f"{user['tcp_port']} {file_name}")

    # ======================================================================
    # Internals
    # ======================================================================
    def _recover(self):
        """Rebuild incidents after a restart. Retransmission timers do not
        survive a crash, so anything still PENDING becomes UNCONFIRMED."""
        with self.db.lock:
            stored = dict(self.db.incidents)
        for incident_id, data in stored.items():
            try:
                incident = Incident.from_dict(data)
            except TypeError:
                log.warning("Skipping unreadable incident record %s", incident_id)
                continue
            changed = False
            for per_user in incident.deliveries.values():
                for name, state in per_user.items():
                    if state == PENDING:
                        per_user[name] = UNCONFIRMED
                        changed = True
            self.incidents[incident_id] = incident
            if changed:
                self._persist(incident)
        if self.incidents:
            log.info("Recovered %d incident(s) from disk", len(self.incidents))

    def _persist(self, incident: Incident):
        self.db.add_incident(incident.incident_id, incident.to_dict())

    def _next_incident_id(self):
        # max+1 instead of len+1: unique even across restarts and gaps.
        nums = [int(i[3:]) for i in self.incidents if i[3:].isdigit()]
        return f"INC{(max(nums) + 1) if nums else 1:03d}"

    def _check_owner(self, incident_id, address):
        incident = self.incidents.get(incident_id)
        if incident is None:
            return None, "Unknown_Incident"
        if not incident.is_active:
            return None, "Incident_Closed"
        sender = self._user_by_address(address)
        if sender is None:
            return None, "Not_Registered"
        if sender[0] != incident.publisher:
            return None, "Not_Incident_Publisher"
        return incident, None

    def _matching_subscribers(self, incident, include_previous=False):
        users = self._users_snapshot()
        subs = self._subscriptions_snapshot()
        targets = []
        for name, user in users.items():
            if user.get("role") not in SUBSCRIBER_ROLES:
                continue
            matches = any(incident.matches(s["zone"], s["type"]) for s in subs.get(name, []))
            if matches or (include_previous and name in incident.recipients):
                targets.append((name, (user["ip"], int(user["udp_port"]))))
        return targets

    def _user_by_address(self, address) -> Optional[Tuple[str, dict]]:
        """PUBLISH/UPDATE/CLOSE carry no name, so the sender is identified by
        the (IP, UDP port) it registered with.  Falls back to port-only when
        the registered IP differs (e.g. 127.0.0.1 vs a LAN IP) and the port
        is unique."""
        ip, port = address
        users = self._users_snapshot()
        exact = [(n, u) for n, u in users.items()
                 if u["ip"] == ip and int(u["udp_port"]) == port]
        if exact:
            return exact[0]
        by_port = [(n, u) for n, u in users.items() if int(u["udp_port"]) == port]
        return by_port[0] if len(by_port) == 1 else None

    def _users_snapshot(self):
        with self.db.lock:
            return dict(self.db.users)

    def _subscriptions_snapshot(self):
        with self.db.lock:
            return {n: list(s) for n, s in self.db.subscriptions.items()}

    def _send(self, message, addr):
        log.info("SEND to %s:%s  %s", addr[0], addr[1], message)
        try:
            self._send_raw(message, addr)
        except OSError as e:
            log.warning("Send to %s failed: %s", addr, e)

    @staticmethod
    def _deny(kind, rq, reason):
        log.info("%s %s %s", kind, rq, reason)
        return f"{kind} {rq} {reason}"

    @staticmethod
    def _in_background(fn, *args):
        threading.Thread(target=fn, args=args, daemon=True).start()
