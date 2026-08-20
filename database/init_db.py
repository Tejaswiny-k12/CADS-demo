"""
CADS Demo — Database Initialisation
Run this ONCE to create the SQLite database and tables.
SQLite = zero setup, file-based, perfect for demo.
In production this would be InfluxDB + PostgreSQL + MongoDB.
"""

import json
import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cads.db")


def _column_exists(conn, table_name, column_name):
    c = conn.cursor()
    c.execute(f"PRAGMA table_info({table_name})")
    columns = [row[1] for row in c.fetchall()]
    return column_name in columns

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # ── Table 1: packets ─────────────────────────────────────────────────────
    # Every packet received is logged here — pass or fail
    c.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT    NOT NULL,
            device_id       TEXT    NOT NULL,
            device_name     TEXT    NOT NULL,
            ttl_expiry      REAL    NOT NULL,
            ttl_remaining   REAL    NOT NULL,

            -- Gate 1 check results
            check_registered    INTEGER NOT NULL DEFAULT 0,
            check_dbi_signature INTEGER NOT NULL DEFAULT 0,
            check_ttl           INTEGER NOT NULL DEFAULT 0,
            check_hash          INTEGER NOT NULL DEFAULT 0,
            check_popc          INTEGER NOT NULL DEFAULT 0,
            check_csm           INTEGER NOT NULL DEFAULT 0,
            check_mba           INTEGER NOT NULL DEFAULT 0,

            -- Final verdict
            gate1_pass      INTEGER NOT NULL DEFAULT 0,
            reject_reason   TEXT,

            -- Performance instrumentation
            verification_latency_ms REAL,
            end_to_end_latency_ms   REAL,

            -- Raw sensor data (only populated if gate1_pass = 1)
            heart_rate      REAL,
            body_temp       REAL,
            battery_level   REAL,
            signal_strength REAL,

            -- Attack simulation flag
            attack_type     TEXT DEFAULT 'NONE'
        )
    """)

    # ── Table 2: alerts ───────────────────────────────────────────────────────
    # Security alerts — every rejection creates an alert
    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            device_id   TEXT    NOT NULL,
            device_name TEXT    NOT NULL,
            severity    TEXT    NOT NULL,   -- LOW, MEDIUM, HIGH, CRITICAL
            cause       TEXT    NOT NULL,   -- EXPIRED_TTL, DBI_INVALID etc.
            detail      TEXT,
            acknowledged INTEGER NOT NULL DEFAULT 0
        )
    """)

    # ── Table 3: devices ──────────────────────────────────────────────────────
    # Device registry — mirrors device_registry.json but in DB for live updates
    c.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            device_id       TEXT PRIMARY KEY,
            device_name     TEXT NOT NULL,
            status          TEXT NOT NULL DEFAULT 'ACTIVE',
            threat_score    INTEGER NOT NULL DEFAULT 0,
            packets_sent    INTEGER NOT NULL DEFAULT 0,
            packets_rejected INTEGER NOT NULL DEFAULT 0,
            last_seen       TEXT
        )
    """)

    # ── Table 4: BCE events ─────────────────────────────────────────────────
    # Tracks blocked C2 / unauthorized egress attempts
    c.execute("""
        CREATE TABLE IF NOT EXISTS bce_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            device_name TEXT NOT NULL,
            target_host TEXT NOT NULL,
            target_port INTEGER NOT NULL,
            blocked     INTEGER NOT NULL DEFAULT 1,
            reason      TEXT
        )
    """)

    c.execute("""
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

    c.execute("""
        CREATE TABLE IF NOT EXISTS gate_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            session_id TEXT,
            gate_number INTEGER NOT NULL,
            gate_name TEXT NOT NULL,
            result TEXT NOT NULL,
            event_time TEXT NOT NULL,
            decision_time TEXT,
            reason TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS device_posture (
            device_id TEXT PRIMARY KEY,
            device_type TEXT NOT NULL DEFAULT 'Unknown',
            firmware_version TEXT NOT NULL DEFAULT 'Unknown',
            last_patch_date TEXT,
            trustzone_attestation TEXT NOT NULL DEFAULT 'UNKNOWN',
            certificate_validity TEXT NOT NULL DEFAULT 'UNKNOWN',
            enrollment_status TEXT NOT NULL DEFAULT 'UNKNOWN'
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS behavioral_scores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            score REAL NOT NULL,
            recorded_at TEXT NOT NULL,
            deviation TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS network_telemetry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT,
            event_type TEXT NOT NULL,
            broker TEXT,
            tls_result TEXT,
            topic TEXT,
            observed_at TEXT NOT NULL,
            detail TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS audit_trail (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT,
            confirmation_hash TEXT NOT NULL,
            block_timestamp TEXT NOT NULL,
            source TEXT NOT NULL DEFAULT 'BCE'
        )
    """)

    conn.commit()
    conn.close()
    print(f"[✓] Database initialised → {DB_PATH}")


def ensure_schema():
    """
    Idempotent migration helper for already-initialized demo databases.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    packets_additions = {
        "check_csm": "INTEGER NOT NULL DEFAULT 0",
        "check_mba": "INTEGER NOT NULL DEFAULT 0",
        "verification_latency_ms": "REAL",
        "end_to_end_latency_ms": "REAL",
    }

    for column_name, column_type in packets_additions.items():
        if not _column_exists(conn, "packets", column_name):
            c.execute(f"ALTER TABLE packets ADD COLUMN {column_name} {column_type}")

    c.execute("""
        CREATE TABLE IF NOT EXISTS bce_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            device_name TEXT NOT NULL,
            target_host TEXT NOT NULL,
            target_port INTEGER NOT NULL,
            blocked     INTEGER NOT NULL DEFAULT 1,
            reason      TEXT
        )
    """)

    c.execute("""
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

    c.execute("""
        CREATE TABLE IF NOT EXISTS gate_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            session_id TEXT,
            gate_number INTEGER NOT NULL,
            gate_name TEXT NOT NULL,
            result TEXT NOT NULL,
            event_time TEXT NOT NULL,
            decision_time TEXT,
            reason TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS device_posture (
            device_id TEXT PRIMARY KEY,
            device_type TEXT NOT NULL DEFAULT 'Unknown',
            firmware_version TEXT NOT NULL DEFAULT 'Unknown',
            last_patch_date TEXT,
            trustzone_attestation TEXT NOT NULL DEFAULT 'UNKNOWN',
            certificate_validity TEXT NOT NULL DEFAULT 'UNKNOWN',
            enrollment_status TEXT NOT NULL DEFAULT 'UNKNOWN'
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS behavioral_scores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            score REAL NOT NULL,
            recorded_at TEXT NOT NULL,
            deviation TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS network_telemetry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT,
            event_type TEXT NOT NULL,
            broker TEXT,
            tls_result TEXT,
            topic TEXT,
            observed_at TEXT NOT NULL,
            detail TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS audit_trail (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT,
            confirmation_hash TEXT NOT NULL,
            block_timestamp TEXT NOT NULL,
            source TEXT NOT NULL DEFAULT 'BCE'
        )
    """)

    conn.commit()
    conn.close()
    print("[✓] Schema migration check complete")


def seed_devices():
    """
    Pre-register our simulated devices.
    In real CADS this happens at manufacture via provisioning pipeline.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    registry_path = os.path.abspath(os.path.join(os.path.dirname(DB_PATH), "..", "keys", "device_registry.json"))

    devices = []
    if os.path.exists(registry_path):
        with open(registry_path, "r", encoding="utf-8") as f:
            registry = json.load(f)

        devices.append(
            (
                registry.get("device_id", "SIM-ECG-01-DEVICE-ID"),
                registry.get("device_name", "SIM-ECG-01"),
                registry.get("status", "ACTIVE"),
            )
        )
    else:
        devices.append(("SIM-ECG-01-DEVICE-ID", "SIM-ECG-01", "ACTIVE"))

    for device_id, device_name, status in devices:
        c.execute("""
            INSERT OR IGNORE INTO devices
                (device_id, device_name, status, threat_score)
            VALUES (?, ?, ?, 0)
        """, (device_id, device_name, status))

    conn.commit()
    conn.close()
    print(f"[✓] {len(devices)} simulated device(s) registered in DB")


if __name__ == "__main__":
    print("\n=== CADS Database Initialisation ===\n")
    init_db()
    ensure_schema()
    seed_devices()
    print("\n=== Done. Database ready. ===\n")