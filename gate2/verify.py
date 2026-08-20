"""Gate 2 device authentication: ECDSA challenge-response, ECDH, and MBA."""

import hashlib
import os
import secrets
import sqlite3
import time
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "database", "cads.db")
IST_TZ = timezone(timedelta(hours=5, minutes=30))
CHALLENGE_WINDOW_SECONDS = 5


def now_ist_str():
    return datetime.now(IST_TZ).isoformat(timespec="seconds")


def _signed_message(response):
    return "|".join(
        [
            "CADS-GATE2",
            response["device_id"],
            response["nonce"],
            str(response["timestamp_ms"]),
            response["ephemeral_public_key"],
            response.get("trust_state", "PROVISIONAL"),
        ]
    ).encode()


def _load_public_key(value):
    if hasattr(value, "verify"):
        return value
    if isinstance(value, str):
        value = value.encode()
    try:
        return serialization.load_pem_public_key(value)
    except ValueError:
        return x509.load_pem_x509_certificate(value).public_key()


def _session_key_id(session_key):
    return hashlib.sha256(session_key).hexdigest()[:16]


def validate_mba(observation, expected_baseline=None, history=None):
    """Validate an authentication behavior against an optional model."""
    observation = observation or {}
    expected_baseline = expected_baseline or {}
    history = history or []

    for field_name, bounds in expected_baseline.get("ranges", {}).items():
        value = observation.get(field_name)
        if value is None or not isinstance(value, (int, float)):
            return False
        if len(bounds) != 2 or value < bounds[0] or value > bounds[1]:
            return False

    expected_sequence = expected_baseline.get("sequence")
    if expected_sequence and observation.get("sequence") != expected_sequence:
        return False

    max_interval = expected_baseline.get("max_interval_ms")
    if max_interval is not None and history:
        previous = history[-1].get("timestamp_ms")
        current = observation.get("timestamp_ms")
        if previous is not None and current is not None and current - previous > max_interval:
            return False
    return True


class Gate2Authenticator:
    """Single-process Gate 2 service with one-use challenges."""

    def __init__(self, public_key_resolver=None, db_path=DB_PATH, window_seconds=CHALLENGE_WINDOW_SECONDS, min_full_samples=3, session_ttl_seconds=120):
        self.public_key_resolver = public_key_resolver
        self.db_path = db_path
        self.window_seconds = window_seconds
        self.min_full_samples = min_full_samples
        self.session_ttl_seconds = session_ttl_seconds
        self._challenges = {}
        self._sessions = {}
        self._history = {}
        self._baselines = {}
        self.ensure_schema()

    def ensure_schema(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS gate2_auth_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL,
                    gate_name TEXT NOT NULL,
                    result TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    session_key_id TEXT,
                    reason TEXT
                )
            """)

    def set_baseline(self, device_id, baseline):
        self._baselines[device_id] = baseline or {}

    def issue_challenge(self, device_id, gate1_session_id, provisional=False):
        if not gate1_session_id:
            raise ValueError("a fresh Gate-1 session is required")
        nonce = secrets.token_urlsafe(32)
        self._challenges[nonce] = {
            "device_id": device_id,
            "gate1_session_id": gate1_session_id,
            "issued_at": time.time(),
            "provisional": bool(provisional),
        }
        return {
            "device_id": device_id,
            "nonce": nonce,
            "issued_at_ms": int(time.time() * 1000),
            "expires_in_ms": int(self.window_seconds * 1000),
        }

    def authenticate(self, response, registered_public_key=None, behavior=None):
        device_id = response.get("device_id", "UNKNOWN")
        nonce = response.get("nonce")
        challenge = self._challenges.pop(nonce, None)
        session_key_id = None
        reason = None
        result = "FAIL"
        gateway_ephemeral_public_key = None

        if challenge is None:
            reason = "NONCE_INVALID_OR_REPLAYED"
        elif challenge["device_id"] != device_id:
            reason = "DEVICE_MISMATCH"
        elif time.time() - challenge["issued_at"] > self.window_seconds:
            reason = "CHALLENGE_EXPIRED"
        else:
            try:
                response_time = float(response["timestamp_ms"]) / 1000
                if abs(time.time() - response_time) > self.window_seconds:
                    raise ValueError("RESPONSE_OUTSIDE_WINDOW")
                public_key = registered_public_key
                if public_key is None and self.public_key_resolver:
                    public_key = self.public_key_resolver(device_id)
                if public_key is None:
                    raise ValueError("REGISTERED_KEY_MISSING")
                public_key = _load_public_key(public_key)
                ephemeral_public = serialization.load_pem_public_key(
                    response["ephemeral_public_key"].encode()
                )
                try:
                    signature = bytes.fromhex(response["signature"])
                except ValueError as exc:
                    raise ValueError("BAD_SIGNATURE") from exc
                public_key.verify(signature, _signed_message(response), ec.ECDSA(hashes.SHA256()))
                if not isinstance(ephemeral_public, ec.EllipticCurvePublicKey):
                    raise ValueError("EPHEMERAL_KEY_INVALID")

                gate_private = ec.generate_private_key(ec.SECP256R1())
                gateway_ephemeral_public_key = gate_private.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode()
                shared_secret = gate_private.exchange(ec.ECDH(), ephemeral_public)
                session_key = HKDF(
                    algorithm=hashes.SHA256(), length=32, salt=None,
                    info=b"CADS-GATE2-SESSION",
                ).derive(shared_secret)
                session_key_id = _session_key_id(session_key)
                mba_ok = validate_mba(behavior, self._baselines.get(device_id), self._history.get(device_id))
                if not mba_ok:
                    reason = "MBA_ANOMALY"
                else:
                    history = self._history.setdefault(device_id, [])
                    history.append(behavior or {})
                    result = "PASS"
                    self._sessions[device_id] = {
                        "session_key": session_key,
                        "session_key_id": session_key_id,
                        "trust": "FULL" if len(history) >= self.min_full_samples else "PROVISIONAL",
                        "expires_at": time.time() + self.session_ttl_seconds,
                    }
            except (KeyError, TypeError, ValueError, UnicodeError) as exc:
                reason = str(exc) or "AUTHENTICATION_FAILED"
            except Exception:
                reason = "BAD_SIGNATURE"

        self._log(device_id, result, session_key_id, reason)
        return {
            "device_id": device_id,
            "gate_name": "gate2_auth",
            "result": result,
            "timestamp": now_ist_str(),
            "session_key_id": session_key_id,
            "reason": reason,
            "trust": self._sessions.get(device_id, {}).get("trust"),
            "gateway_ephemeral_public_key": gateway_ephemeral_public_key,
        }

    def get_session_key(self, device_id):
        """Return the current C-TTL session key, or None after expiry."""
        session = self._sessions.get(device_id)
        if not session or time.time() >= session["expires_at"]:
            self._sessions.pop(device_id, None)
            return None
        return session["session_key"]

    def _log(self, device_id, result, session_key_id, reason):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """INSERT INTO gate2_auth_logs
                (device_id, gate_name, result, timestamp, session_key_id, reason)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (device_id, "gate2_auth", result, now_ist_str(), session_key_id, reason),
            )


def build_response(private_key, challenge, behavior=None, trust_state="PROVISIONAL"):
    """Build a device-side response for a Gate-2 challenge."""
    ephemeral_private = ec.generate_private_key(ec.SECP256R1())
    ephemeral_public = ephemeral_private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    response = {
        "device_id": challenge["device_id"],
        "nonce": challenge["nonce"],
        "timestamp_ms": int(time.time() * 1000),
        "ephemeral_public_key": ephemeral_public,
        "trust_state": trust_state,
    }
    response["signature"] = private_key.sign(_signed_message(response), ec.ECDSA(hashes.SHA256())).hex()
    response["behavior"] = behavior or {}
    return response, ephemeral_private