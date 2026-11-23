"""
incident.py  -  Part B: the shared Incident data structure for CENRS.

This is the ONE definition of "what an incident looks like" that the whole
team agrees on:

  * B (alerts) creates / updates / closes incidents and fills in delivery info.
  * A (persistence) stores them in data/incidents.json via Incident.to_dict()
    and loads them back with Incident.from_dict().  A never needs to know the
    field list; it just stores the dict under its incident_id.
  * D (attachments) looks an incident up to answer ATTACH_REQ
    (see AlertManager.get_attachment_source()).
  * GET_ACTIVE_ALERTS (TCP sync) sends Incident.to_record() lines.

Stored JSON shape (one entry of data/incidents.json, keyed by incident_id):

{
    "incident_id": "INC001",
    "version": 2,
    "status": "ACTIVE",                # ACTIVE | CLOSED
    "category": "FIRE",
    "location": "HALL",
    "severity": "WARNING",             # INFO | WARNING | CRITICAL
    "title": "Fire Controlled",        # stored with real spaces
    "description": "Remain outside",
    "attachment": "evacuation_map.pdf",# or "NONE"
    "publisher": "CampusSecurity",     # registered name of the creator
    "close_reason": null,              # text once CLOSED
    "created_at": 1700000000.0,
    "updated_at": 1700000100.0,
    "recipients": ["Alice", "Bob"],    # everyone ever sent this incident
    "deliveries": {                    # per version -> per user
        "1": {"Alice": "CONFIRMED", "Bob": "UNCONFIRMED"},
        "2": {"Alice": "SENT", "Bob": "SENT"}
    }
}

Delivery states:
    SENT         - sent, no ack required (INFO / WARNING)
    PENDING      - sent, waiting for ALERT_ACK (CRITICAL / ALL_CLEAR)
    CONFIRMED    - ALERT_ACK received
    UNCONFIRMED  - 3 attempts made, no ack (or server restarted while pending)
    SUPERSEDED   - a newer version was sent before this one was acked
"""

import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Shared constants (A's REGISTERED reply should use these same lists)
# ---------------------------------------------------------------------------
LOCATIONS = ["HALL", "EV", "JMSB", "LOYOLA", "SGW", "ALL"]
CATEGORIES = ["FIRE", "SECURITY", "WEATHER", "POWER", "BUILDING", "GENERAL", "ALL"]
SEVERITIES = ["INFO", "WARNING", "CRITICAL"]
USER_STATUSES = ["SAFE", "NEED_HELP", "LEFT_AREA"]

PUBLISHER_ROLES = ("PUBLISHER", "BOTH")
SUBSCRIBER_ROLES = ("SUBSCRIBER", "BOTH")

ACTIVE = "ACTIVE"
CLOSED = "CLOSED"

# delivery states
SENT = "SENT"
PENDING = "PENDING"
CONFIRMED = "CONFIRMED"
UNCONFIRMED = "UNCONFIRMED"
SUPERSEDED = "SUPERSEDED"


# ---------------------------------------------------------------------------
# Text encoding on the wire
# ---------------------------------------------------------------------------
# Every protocol message is space-separated tokens.  Title, Description,
# close Reason and ALL_CLEAR Message may contain spaces, so on the wire a
# space is written as "_" (exactly like the spec examples: Fire_Alarm,
# Evacuate_Building).  Inside the server they are stored with real spaces.
def encode_text(text: str) -> str:
    text = (text or "").strip()
    return text.replace(" ", "_") if text else "NONE"


def decode_text(token: str) -> str:
    return token.replace("_", " ")


@dataclass
class Incident:
    incident_id: str
    category: str
    location: str
    severity: str
    title: str
    description: str
    attachment: str
    publisher: str
    version: int = 1
    status: str = ACTIVE
    close_reason: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    recipients: List[str] = field(default_factory=list)
    deliveries: Dict[str, Dict[str, str]] = field(default_factory=dict)

    # ---------------- persistence (used by A) ----------------
    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Incident":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})

    # ---------------- helpers ----------------
    @property
    def is_active(self) -> bool:
        return self.status == ACTIVE

    def has_attachment(self) -> bool:
        return bool(self.attachment) and self.attachment.upper() != "NONE"

    def matches(self, sub_location: str, sub_category: str) -> bool:
        """Spec 2.2: exact value or wildcard ALL on the subscription side.
        Our extra assumption: an incident published with location ALL
        (campus-wide) or category ALL reaches every location / category."""
        loc_ok = sub_location in ("ALL", self.location) or self.location == "ALL"
        cat_ok = sub_category in ("ALL", self.category) or self.category == "ALL"
        return loc_ok and cat_ok

    def set_delivery(self, name: str, state: str, version: Optional[int] = None):
        v = str(version if version is not None else self.version)
        self.deliveries.setdefault(v, {})[name] = state

    def get_delivery(self, name: str, version: Optional[int] = None) -> Optional[str]:
        v = str(version if version is not None else self.version)
        return self.deliveries.get(v, {}).get(name)

    # ---------------- wire formats ----------------
    def alert_message(self, rq) -> str:
        # ALERT RQ# Incident_ID Version Category Location Severity Title Description Attachment
        return (f"ALERT {rq} {self.incident_id} {self.version} {self.category} "
                f"{self.location} {self.severity} {encode_text(self.title)} "
                f"{encode_text(self.description)} {self.attachment}")

    def update_message(self, rq) -> str:
        # ALERT_UPDATE RQ# Incident_ID Version Severity Title Description
        return (f"ALERT_UPDATE {rq} {self.incident_id} {self.version} "
                f"{self.severity} {encode_text(self.title)} "
                f"{encode_text(self.description)}")

    def all_clear_message(self, rq) -> str:
        # ALL_CLEAR RQ# Incident_ID Version Message
        return (f"ALL_CLEAR {rq} {self.incident_id} {self.version} "
                f"{encode_text(self.close_reason or 'Incident Closed')}")

    def to_record(self) -> str:
        """One line per incident for the ACTIVE_ALERTS TCP reply (spec 2.10):
        Incident_ID Version Category Location Severity Status Title Description Attachment"""
        return (f"{self.incident_id} {self.version} {self.category} {self.location} "
                f"{self.severity} {self.status} {encode_text(self.title)} "
                f"{encode_text(self.description)} {self.attachment}")
