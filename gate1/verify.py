"""
CADS Demo — Gate 1 Cryptographic Verification Pipeline
Subscribes to MQTT, runs deterministic checks on every packet, writes results to DB.

Checks represented in Gate 1 telemetry:
    1. CSM packet-structure validation
    2. Device registered and ACTIVE
    3. DBI signature valid
    4. C-TTL not expired
    5. Payload hash matches
    6. PoPC chain present and well-formed
    7. MBA physiological/behavioral sanity check
"""

import json
import time
import hashlib
import sqlite3
import os
import sys
from datetime import datetime, timedelta, timezone

import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYS_DIR = os.path.join(BASE_DIR, "keys")
DB_PATH  = os.path.join(BASE_DIR, "database", "cads.db")

# ── Config ────────────────────────────────────────────────────────────────────
MQTT_BROKER = "localhost"
MQTT_PORT   = 1883
MQTT_TOPIC  = "cads/telemetry"
IST_TZ = timezone(timedelta(hours=5, minutes=30))

# Severity mapping for reject reasons
SEVERITY_MAP = {
    "CSM_INVALID":          "HIGH",
    "DEVICE_NOT_REGISTERED": "HIGH",
    "DEVICE_QUARANTINED":    "CRITICAL",
    "DBI_INVALID":           "CRITICAL",
    "EXPIRED_TTL":           "MEDIUM",
    "HASH_MISMATCH":         "CRITICAL",
    "POPC_MISSING":          "HIGH",
    "POPC_MALFORMED":        "HIGH",
    "MBA_ANOMALY":           "MEDIUM",
}

REQUIRED_PACKET_FIELDS = {
    "device_id": str,
    "device_name": str,
    "session_key_enc": str,
    "payload_enc": str,
    "ttl_expiry": (int, float),
    "pop_chain": list,
    "dbi_signature": str,
    "payload_hash": str,
}

MBA_RANGES = {
    "heart_rate": (45.0, 130.0),
    "body_temp": (35.0, 38.3),
    "battery_level": (15.0, 100.0),
    "signal_strength": (20.0, 100.0),
}

# ── Load device public key ────────────────────────────────────────────────────
def load_device_public_key():
    with open(os.path.join(KEYS_DIR, "device_public.pem"), "rb") as f:
        return serialization.load_pem_public_key(f.read())

# ── DB helpers ────────────────────────────────────────────────────────────────
def get_db():
    return sqlite3.connect(DB_PATH)


def now_ist_str():
    return datetime.now(IST_TZ).isoformat(timespec="seconds")


def ensure_gate_schema():
    conn = get_db()
    c = conn.cursor()
    c.execute("PRAGMA table_info(packets)")
    existing_columns = {row[1] for row in c.fetchall()}

    additions = {
        "check_csm": "INTEGER NOT NULL DEFAULT 0",
        "check_mba": "INTEGER NOT NULL DEFAULT 0",
        "verification_latency_ms": "REAL",
        "end_to_end_latency_ms": "REAL",
    }

    for column_name, ddl in additions.items():
        if column_name not in existing_columns:
            c.execute(f"ALTER TABLE packets ADD COLUMN {column_name} {ddl}")

    conn.commit()
    conn.close()

def get_device(device_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,))
    row = c.fetchone()
    conn.close()
    return row

def log_packet(data):
    conn = get_db()
    c = conn.cursor()
    ts = now_ist_str()
    c.execute("""
        INSERT INTO packets (
            timestamp, device_id, device_name, ttl_expiry, ttl_remaining,
            check_registered, check_dbi_signature, check_ttl, check_hash, check_popc,
            check_csm, check_mba,
            gate1_pass, reject_reason,
            verification_latency_ms, end_to_end_latency_ms,
            heart_rate, body_temp, battery_level, signal_strength,
            attack_type
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        ts,
        data["device_id"],
        data.get("device_name", "UNKNOWN"),
        data["ttl_expiry"],
        data["ttl_remaining"],
        int(data["check_registered"]),
        int(data["check_dbi_signature"]),
        int(data["check_ttl"]),
        int(data["check_hash"]),
        int(data["check_popc"]),
        int(data["check_csm"]),
        int(data["check_mba"]),
        int(data["gate1_pass"]),
        data.get("reject_reason"),
        data.get("verification_latency_ms"),
        data.get("end_to_end_latency_ms"),
        data.get("heart_rate"),
        data.get("body_temp"),
        data.get("battery_level"),
        data.get("signal_strength"),
        data.get("attack_type", "NONE"),
    ))
    conn.commit()
    conn.close()

def log_alert(device_id, device_name, cause, detail):
    severity = SEVERITY_MAP.get(cause, "MEDIUM")
    conn = get_db()
    c = conn.cursor()
    ts = now_ist_str()
    c.execute("""
        INSERT INTO alerts (timestamp, device_id, device_name, severity, cause, detail)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (ts, device_id, device_name, severity, cause, detail))
    conn.commit()
    conn.close()

def update_device_stats(device_id, accepted, threat_increment=0):
    conn = get_db()
    c = conn.cursor()
    ts = now_ist_str()
    if accepted:
        c.execute("""
            UPDATE devices SET
                packets_sent = packets_sent + 1,
                last_seen = ?,
                threat_score = MAX(0, threat_score - 1)
            WHERE device_id = ?
        """, (ts, device_id))
    else:
        c.execute("""
            UPDATE devices SET
                packets_rejected = packets_rejected + 1,
                last_seen = ?,
                threat_score = MIN(100, threat_score + ?)
            WHERE device_id = ?
        """, (ts, threat_increment, device_id))
    conn.commit()
    conn.close()


def check_csm_structure(packet):
    for field_name, expected_type in REQUIRED_PACKET_FIELDS.items():
        if field_name not in packet:
            return False
        if not isinstance(packet[field_name], expected_type):
            return False
    return True


def verify_dbi_signature(packet, device_public_key):
    signing_input = (
        packet.get("device_id", "") +
        packet.get("session_key_enc", "") +
        str(packet.get("ttl_expiry", "")) +
        packet.get("payload_hash", "")
    ).encode()

    sig_bytes = bytes.fromhex(packet.get("dbi_signature", ""))
    device_public_key.verify(sig_bytes, signing_input, ec.ECDSA(hashes.SHA256()))
    return True


def check_ttl_valid(packet, now_ms=None):
    current_ms = time.time() * 1000 if now_ms is None else now_ms
    ttl_expiry = packet.get("ttl_expiry", 0)
    ttl_remaining = (ttl_expiry - current_ms) / 1000
    return ttl_remaining > 0, ttl_remaining


def check_payload_hash(packet):
    payload_enc_bytes = bytes.fromhex(packet.get("payload_enc", ""))
    computed_hash = hashlib.sha256(payload_enc_bytes).hexdigest()
    claimed_hash = packet.get("payload_hash", "")
    return computed_hash == claimed_hash


def check_popc_chain(packet):
    pop_chain = packet.get("pop_chain", [])
    if not pop_chain:
        return False, "POPC_MISSING"
    if not isinstance(pop_chain[0], dict):
        return False, "POPC_MALFORMED"
    if pop_chain[0].get("hop_type") != "DEVICE_ORIGIN":
        return False, "POPC_MALFORMED"
    return True, None


def check_mba(sensor_data):
    if not isinstance(sensor_data, dict) or not sensor_data:
        return True
    for metric_name, (min_val, max_val) in MBA_RANGES.items():
        val = sensor_data.get(metric_name)
        if val is None:
            continue
        if val < min_val or val > max_val:
            return False
    return True


# ── Gate 1 — Verification Pipeline ───────────────────────────────────────────
def run_gate1(packet, device_public_key):
    """
    Runs deterministic Gate 1 checks.
    Returns result dict with pass/fail per check and final verdict.
    """
    started = time.perf_counter()

    device_id   = packet.get("device_id", "UNKNOWN")
    device_name = packet.get("device_name", "UNKNOWN")
    attack_type = packet.get("attack_type", "NONE")

    result = {
        "device_id":          device_id,
        "device_name":        device_name,
        "ttl_expiry":         packet.get("ttl_expiry", 0),
        "ttl_remaining":      0,
        "check_registered":   False,
        "check_dbi_signature":False,
        "check_ttl":          False,
        "check_hash":         False,
        "check_popc":         False,
        "check_csm":          False,
        "check_mba":          False,
        "gate1_pass":         False,
        "reject_reason":      None,
        "attack_type":        attack_type,
        "verification_latency_ms": None,
        "end_to_end_latency_ms": None,
    }

    # ── Check 0: CSM Structural Validation ──────────────────────────────────
    if not check_csm_structure(packet):
        result["reject_reason"] = "CSM_INVALID"
        result["verification_latency_ms"] = (time.perf_counter() - started) * 1000
        _print_result(result)
        return result
    result["check_csm"] = True

    # ── Check 1: Device Registered ───────────────────────────────────────────
    device_row = get_device(device_id)
    if device_row is None:
        result["reject_reason"] = "DEVICE_NOT_REGISTERED"
        result["verification_latency_ms"] = (time.perf_counter() - started) * 1000
        _print_result(result)
        return result
    result["check_registered"] = True

    # Check device is not quarantined
    # device_row columns: device_id, device_name, status, threat_score, ...
    status = device_row[2]
    if status == "QUARANTINE":
        result["reject_reason"] = "DEVICE_QUARANTINED"
        result["verification_latency_ms"] = (time.perf_counter() - started) * 1000
        _print_result(result)
        return result

    # ── Check 2: DBI Signature ───────────────────────────────────────────────
    try:
        verify_dbi_signature(packet, device_public_key)
        result["check_dbi_signature"] = True
    except Exception:
        result["reject_reason"] = "DBI_INVALID"
        result["verification_latency_ms"] = (time.perf_counter() - started) * 1000
        _print_result(result)
        return result

    # ── Check 3: TTL Not Expired ─────────────────────────────────────────────
    is_ttl_valid, ttl_remaining = check_ttl_valid(packet)
    result["ttl_remaining"] = ttl_remaining
    if not is_ttl_valid:
        result["reject_reason"] = "EXPIRED_TTL"
        result["verification_latency_ms"] = (time.perf_counter() - started) * 1000
        _print_result(result)
        return result
    result["check_ttl"] = True

    # ── Check 4: Payload Hash ────────────────────────────────────────────────
    try:
        if not check_payload_hash(packet):
            result["reject_reason"] = "HASH_MISMATCH"
            result["verification_latency_ms"] = (time.perf_counter() - started) * 1000
            _print_result(result)
            return result
        result["check_hash"] = True
    except Exception:
        result["reject_reason"] = "HASH_MISMATCH"
        result["verification_latency_ms"] = (time.perf_counter() - started) * 1000
        _print_result(result)
        return result

    # ── Check 5: PoPC Chain ──────────────────────────────────────────────────
    popc_ok, popc_reason = check_popc_chain(packet)
    if not popc_ok:
        result["reject_reason"] = popc_reason
        result["verification_latency_ms"] = (time.perf_counter() - started) * 1000
        _print_result(result)
        return result
    result["check_popc"] = True

    # ── Check 6: MBA behavioral sanity ───────────────────────────────────────
    sensor_data = packet.get("sensor_data", {})
    if not check_mba(sensor_data):
        result["reject_reason"] = "MBA_ANOMALY"
        result["verification_latency_ms"] = (time.perf_counter() - started) * 1000
        _print_result(result)
        return result
    result["check_mba"] = True

    # ── All checks passed ────────────────────────────────────────────────────
    result["gate1_pass"] = True

    # Decode payload to extract sensor values (for storage)
    # In real CADS this uses the cloud private key to decrypt
    # For demo: simulator puts sensor data in packet for simplicity
    # Real implementation: decrypt session_key_enc → decrypt payload_enc
    result["heart_rate"] = sensor_data.get("heart_rate")
    result["body_temp"] = sensor_data.get("body_temp")
    result["battery_level"] = sensor_data.get("battery_level")
    result["signal_strength"] = sensor_data.get("signal_strength")

    result["verification_latency_ms"] = (time.perf_counter() - started) * 1000
    pkt_timestamp = packet.get("packet_timestamp")
    if isinstance(pkt_timestamp, (int, float)):
        result["end_to_end_latency_ms"] = max(0.0, (time.time() * 1000) - pkt_timestamp)

    _print_result(result)
    return result


def _print_result(r):
    status = "✓ ACCEPTED" if r["gate1_pass"] else f"✗ REJECTED [{r['reject_reason']}]"
    checks = (
        f"REG={'✓' if r['check_registered'] else '✗'} "
        f"DBI={'✓' if r['check_dbi_signature'] else '✗'} "
        f"CSM={'✓' if r['check_csm'] else '✗'} "
        f"TTL={'✓' if r['check_ttl'] else '✗'}({r['ttl_remaining']:.1f}s) "
        f"HASH={'✓' if r['check_hash'] else '✗'} "
        f"POPC={'✓' if r['check_popc'] else '✗'} "
        f"MBA={'✓' if r['check_mba'] else '✗'}"
    )
    latency_ms = r.get("verification_latency_ms")
    latency_str = f" | verify={latency_ms:.2f}ms" if latency_ms is not None else ""
    print(f"[GATE1] {r['device_name']} | {checks} | {status}{latency_str}")


# ── MQTT message handler ──────────────────────────────────────────────────────
def on_message(client, userdata, msg):
    device_public_key = userdata["device_public_key"]

    try:
        packet = json.loads(msg.payload.decode())
    except Exception as e:
        print(f"[GATE1] Failed to parse packet: {e}")
        return

    device_id   = packet.get("device_id", "UNKNOWN")
    device_name = packet.get("device_name", "UNKNOWN")

    # Run Gate 1
    result = run_gate1(packet, device_public_key)

    # Log to database
    log_packet(result)

    if result["gate1_pass"]:
        update_device_stats(device_id, accepted=True)
    else:
        # Threat increment depends on severity
        threat_map = {
            "CSM_INVALID":           8,
            "DBI_INVALID":           15,
            "HASH_MISMATCH":         15,
            "DEVICE_NOT_REGISTERED": 10,
            "DEVICE_QUARANTINED":    20,
            "EXPIRED_TTL":            5,
            "POPC_MISSING":           8,
            "POPC_MALFORMED":        10,
            "MBA_ANOMALY":            7,
        }
        increment = threat_map.get(result["reject_reason"], 5)
        update_device_stats(device_id, accepted=False, threat_increment=increment)
        log_alert(
            device_id, device_name,
            result["reject_reason"],
            f"Attack type: {result['attack_type']} | TTL remaining: {result['ttl_remaining']:.1f}s"
        )


def on_connect(client, userdata, flags, rc):
    if rc == 0:
        client.subscribe(MQTT_TOPIC)
        print(f"[GATE1] Connected to broker. Listening on '{MQTT_TOPIC}'...")
    else:
        print(f"[GATE1] Connection failed: {rc}")


# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n=== CADS Gate 1 — Cryptographic Verification Pipeline ===\n")

    if not os.path.exists(DB_PATH):
        print(f"[ERROR] Database not found at {DB_PATH}")
        print("Run: python database/init_db.py first")
        sys.exit(1)

    ensure_gate_schema()

    device_public_key = load_device_public_key()
    print(f"[DBI] Device public key loaded from registry")
    print(f"[DB]  Connected to {DB_PATH}\n")

    client = mqtt.Client(userdata={"device_public_key": device_public_key})
    client.on_connect = on_connect
    client.on_message = on_message

    client.connect(MQTT_BROKER, MQTT_PORT, 60)

    try:
        client.loop_forever()
    except KeyboardInterrupt:
        print("\n[GATE1] Stopped.")
        