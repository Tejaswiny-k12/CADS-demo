"""
CADS Demo — IoMT Device Simulator
Simulates an ARM Cortex-M33 IoMT device running CADS firmware.
No real hardware needed — all cryptographic operations are real.

Modes:
  normal  → valid packets, all checks pass
  tamper  → payload modified after signing (HASH_MISMATCH)
  replay  → sends packet with expired TTL (EXPIRED_TTL)
  c2      → attempts connection to unapproved address (BCE_VIOLATION)
  bad_sig → corrupts the DBI signature (DBI_INVALID)
"""

import json
import time
import random
import hashlib
import struct
import os
import sys
import argparse
import sqlite3
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import secrets

from gate2.verify import Gate2Authenticator, build_response, _signed_message

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYS_DIR  = os.path.join(BASE_DIR, "keys")
DB_PATH   = os.path.join(BASE_DIR, "database", "cads.db")


# ── Config ────────────────────────────────────────────────────────────────────
MQTT_BROKER   = "localhost"
MQTT_PORT     = 1883
MQTT_TOPIC    = "cads/telemetry"
SEND_INTERVAL = 3   # seconds between packets
TTL_SECONDS   = 120 # cryptographic time-to-live

# ── Approved endpoints (BCE whitelist) ────────────────────────────────────────
# In real firmware this is compiled in at build time.
# The device can ONLY connect to these addresses.
BCE_APPROVED = [
    ("localhost", 1883),       # MQTT broker
    ("cloud.cads-demo.local", 443),  # cloud backend
]
IST_TZ = timezone(timedelta(hours=5, minutes=30))


def now_ist_str():
    return datetime.now(IST_TZ).isoformat(timespec="seconds")


def log_bce_event(device_name, host, port, blocked, reason):
    if not os.path.exists(DB_PATH):
        return

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    ts = now_ist_str()
    c.execute(
        """
        INSERT INTO bce_events (timestamp, device_name, target_host, target_port, blocked, reason)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (ts, device_name, host, port, int(blocked), reason),
    )
    conn.commit()
    conn.close()


def log_network_event(device_id, event_type, broker, tls_result, topic, detail):
    if not os.path.exists(DB_PATH):
        return
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        INSERT INTO network_telemetry
            (device_id, event_type, broker, tls_result, topic, observed_at, detail)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (device_id, event_type, broker, tls_result, topic, now_ist_str(), detail),
    )
    conn.commit()
    conn.close()

# ── Load keys ─────────────────────────────────────────────────────────────────
def load_keys():
    with open(os.path.join(KEYS_DIR, "device_private.pem"), "rb") as f:
        device_private = serialization.load_pem_private_key(f.read(), password=None)
    with open(os.path.join(KEYS_DIR, "cloud_public.pem"), "rb") as f:
        cloud_public = serialization.load_pem_public_key(f.read())
    with open(os.path.join(KEYS_DIR, "device_public.pem"), "rb") as f:
        device_pub_pem = f.read()

    device_id = hashlib.sha256(device_pub_pem).hexdigest()[:32]
    return device_private, cloud_public, device_id

# ── Generate fake sensor data ────────────────────────────────────────────────
def generate_sensor_data(anomaly=False):
    if anomaly:
        # Out-of-range medical values
        return {
            "heart_rate":      random.uniform(140, 180),
            "body_temp":       random.uniform(38.5, 40.0),
            "battery_level":   random.uniform(5, 15),
            "signal_strength": random.uniform(10, 30),
        }
    else:
        # Normal values
        return {
            "heart_rate":      random.uniform(60, 100),
            "body_temp":       random.uniform(36.1, 37.5),
            "battery_level":   random.uniform(60, 100),
            "signal_strength": random.uniform(70, 100),
        }

# ── BCE check ────────────────────────────────────────────────────────────────
def bce_check(host, port):
    """
    Behavioral Contract Engine — compile-time whitelist check.
    In real firmware the code to connect elsewhere doesn't exist.
    Here we simulate that with a hard check.
    """
    if (host, port) in BCE_APPROVED:
        log_bce_event("SIM-ECG-01", host, port, blocked=False, reason="ALLOWLIST_MATCH")
        log_network_event("SIM-ECG-01", "MQTT_BROKER_CONNECTION", f"{host}:{port}", "SUCCESS", MQTT_TOPIC, "BCE allowlist match")
        return True
    # BCE VIOLATION — log it, return False, never connect
    print(f"[BCE VIOLATION] Attempted connection to {host}:{port} — BLOCKED. No packet sent.")
    log_bce_event("SIM-ECG-01", host, port, blocked=True, reason="BCE_VIOLATION")
    log_network_event("SIM-ECG-01", "MQTT_BROKER_CONNECTION", f"{host}:{port}", "BLOCKED", MQTT_TOPIC, "BCE violation")
    return False

# ── Build CADS packet ────────────────────────────────────────────────────────
def build_cads_packet(device_private, cloud_public, device_id,
                       sensor_data, attack_type="NONE"):
    """
    Assembles a full CADS packet:
      1. Generate ephemeral session key (C-TTL)
      2. Encrypt payload with session key
      3. Encrypt session key with cloud public key
      4. Sign packet header with DBI private key
      5. Build PoPC origin entry
    """

    now_ms     = time.time() * 1000
    ttl_expiry = now_ms + (TTL_SECONDS * 1000)

    # ── Step 1: C-TTL — Generate ephemeral session key ──────────────────────
    session_key = secrets.token_bytes(32)  # AES-256
    nonce       = secrets.token_bytes(12)  # GCM nonce

    # ── Step 2: Encrypt payload ──────────────────────────────────────────────
    payload_json  = json.dumps(sensor_data).encode()
    aesgcm        = AESGCM(session_key)
    payload_enc   = aesgcm.encrypt(nonce, payload_json, None)
    payload_hash  = hashlib.sha256(payload_enc).hexdigest()

    # ── Step 3: Encrypt session key with cloud public key ───────────────────
    # We use ECDH-derived shared secret to wrap the session key
    # (simplified for demo: we store session key + ttl as JSON,
    #  encrypt with cloud's public key via ECIES-style wrapping)
    session_bundle = json.dumps({
        "session_key": session_key.hex(),
        "nonce":       nonce.hex(),
        "ttl_expiry":  ttl_expiry,
    }).encode()

    # For demo: encrypt session bundle using cloud public key with ECDH
    # Real implementation uses full ECIES; demo uses a simplified approach
    ephemeral_key = ec.generate_private_key(ec.SECP256R1())
    shared_secret = ephemeral_key.exchange(
        ec.ECDH(), cloud_public
    )
    # Derive AES key from shared secret
    wrap_key  = hashlib.sha256(shared_secret).digest()
    wrap_nonce = secrets.token_bytes(12)
    wrap_aesgcm = AESGCM(wrap_key)
    session_key_enc = {
        "ephemeral_pub": ephemeral_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode(),
        "ciphertext": wrap_aesgcm.encrypt(wrap_nonce, session_bundle, None).hex(),
        "wrap_nonce": wrap_nonce.hex(),
    }
    session_key_enc_str = json.dumps(session_key_enc)

    # ── DISCARD session key from memory (simulated) ──────────────────────────
    # In real TrustZone-M firmware: explicit memory zeroing
    del session_key

    # ── Step 4: DBI Signature ────────────────────────────────────────────────
    # Sign: device_id + session_key_enc + ttl_expiry + payload_hash
    signing_input = (
        device_id +
        session_key_enc_str +
        str(ttl_expiry) +
        payload_hash
    ).encode()

    signature = device_private.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    dbi_signature = signature.hex()

    # ── Step 5: PoPC origin entry ────────────────────────────────────────────
    pop_chain = [{
        "hop_id":    device_id,
        "hop_type":  "DEVICE_ORIGIN",
        "timestamp": now_ms,
        "hmac":      hashlib.sha256(
            (device_id + str(now_ms)).encode()
        ).hexdigest()
    }]

    # ── Assemble packet ──────────────────────────────────────────────────────
    packet = {
        "device_id":        device_id,
        "device_name":      "SIM-ECG-01",
        "session_key_enc":  session_key_enc_str,
        "payload_enc":      payload_enc.hex(),
        "nonce":            nonce.hex(),
        "ttl_expiry":       ttl_expiry,
        "sensor_data":      sensor_data,
        "pop_chain":        pop_chain,
        "dbi_signature":    dbi_signature,
        "payload_hash":     payload_hash,
        "attack_type":      attack_type,
        "packet_timestamp": now_ms,
    }

    # ── Inject attacks for demo ──────────────────────────────────────────────
    if attack_type == "TAMPER":
        # Simulate MitM modifying payload after signing
        original = bytes.fromhex(packet["payload_enc"])
        tampered = bytes([original[0] ^ 0xFF]) + original[1:]  # flip first byte
        packet["payload_enc"] = tampered.hex()
        print("[ATTACK] Payload tampered — first byte flipped")

    elif attack_type == "REPLAY":
        # Simulate replay attack — set TTL to 10 minutes in the past
        packet["ttl_expiry"] = now_ms - (10 * 60 * 1000)
        print("[ATTACK] TTL set to 10 minutes ago — replay attack")

    elif attack_type == "BAD_SIG":
        # Corrupt the signature
        packet["dbi_signature"] = "deadbeef" * 16
        print("[ATTACK] DBI signature corrupted")

    return packet

# ── Simulate BCE C2 attempt ──────────────────────────────────────────────────
def simulate_c2_attempt():
    """
    Demonstrates BCE blocking a C2 beacon attempt.
    The device 'tries' to connect to a C2 server.
    BCE blocks it before any connection is made.
    """
    c2_host = "evil-c2-server.attacker.com"
    c2_port = 4444
    print(f"\n[SIMULATOR] Simulating C2 beacon attempt to {c2_host}:{c2_port}")
    allowed = bce_check(c2_host, c2_port)
    if not allowed:
        print(f"[BCE] Connection to {c2_host}:{c2_port} STRUCTURALLY BLOCKED")
        print(f"[BCE] No packet transmitted. No network trace generated.\n")
    return not allowed  # True = was blocked


def simulate_gate2_attack(mode):
    """Run a local Gate-2 scenario and persist its audit result."""
    device_private, _, device_id = load_keys()
    authenticator = Gate2Authenticator(db_path=DB_PATH, min_full_samples=3)
    challenge = authenticator.issue_challenge(device_id, gate1_session_id=f"sim-{time.time_ns()}", provisional=True)
    behavior = {"sequence": ["nonce", "signature", "ephemeral-key"], "timestamp_ms": int(time.time() * 1000)}

    if mode == "gate2_mba":
        authenticator.set_baseline(device_id, {"ranges": {"auth_latency_ms": [0, 100]}})
        behavior["auth_latency_ms"] = 900
    response, _ = build_response(device_private, challenge, behavior)

    if mode == "gate2_bad_sig":
        response["signature"] = "00"
    elif mode == "gate2_stale":
        response["timestamp_ms"] -= 10_000
        response["signature"] = device_private.sign(
            _signed_message(response),
            ec.ECDSA(hashes.SHA256()),
        ).hex()

    result = authenticator.authenticate(response, device_private.public_key(), behavior)
    print(f"[GATE2] mode={mode} result={result['result']} reason={result['reason']}")
    if mode == "gate2_replay":
        replay = authenticator.authenticate(response, device_private.public_key(), behavior)
        print(f"[GATE2] replay result={replay['result']} reason={replay['reason']}")
    return result

# ── MQTT callbacks ────────────────────────────────────────────────────────────
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print(f"[MQTT] Connected to broker at {MQTT_BROKER}:{MQTT_PORT}")
    else:
        print(f"[MQTT] Connection failed with code {rc}")

# ── Main loop ─────────────────────────────────────────────────────────────────
def run(mode="normal", count=0, seed=None, send_interval=SEND_INTERVAL):
    if seed is not None:
        random.seed(seed)

    print(f"\n=== CADS Device Simulator ===")
    print(f"Mode: {mode.upper()}")
    print(f"Device: SIM-ECG-01")
    print(f"Broker: {MQTT_BROKER}:{MQTT_PORT}")
    print(f"TTL: {TTL_SECONDS}s per packet")
    if count > 0:
        print(f"Packet Count: {count}")
    if seed is not None:
        print(f"Random Seed: {seed}")
    print("")

    # BCE check for MQTT broker connection
    if not bce_check(MQTT_BROKER, MQTT_PORT):
        print("[FATAL] MQTT broker not in BCE whitelist. Cannot connect.")
        sys.exit(1)

    # Load keys
    device_private, cloud_public, device_id = load_keys()
    print(f"[DBI] Device ID: {device_id}")
    print(f"[DBI] Private key loaded from TrustZone-M partition (simulated)\n")

    # Handle C2 mode separately
    if mode == "c2":
        simulate_c2_attempt()
        print("C2 simulation complete. Exiting.")
        return

    if mode.startswith("gate2_"):
        simulate_gate2_attack(mode)
        return

    # Connect MQTT
    client = mqtt.Client()
    client.on_connect = on_connect
    client.connect(MQTT_BROKER, MQTT_PORT, 60)
    client.loop_start()

    time.sleep(1)  # wait for connection

    packet_count = 0
    try:
        while True:
            packet_count += 1

            # Determine attack type
            attack_type = "NONE"
            if mode == "tamper":
                attack_type = "TAMPER"
            elif mode == "replay":
                attack_type = "REPLAY"
            elif mode == "bad_sig":
                attack_type = "BAD_SIG"

            # Generate sensor data
            sensor_data = generate_sensor_data(anomaly=(mode == "anomaly"))

            # Build CADS packet
            packet = build_cads_packet(
                device_private, cloud_public, device_id,
                sensor_data, attack_type
            )

            # Publish
            payload = json.dumps(packet)
            client.publish(MQTT_TOPIC, payload)

            ttl_remaining = (packet["ttl_expiry"] - time.time()*1000) / 1000
            print(
                f"[PKT #{packet_count:04d}] "
                f"HR={sensor_data['heart_rate']:.1f}bpm "
                f"Temp={sensor_data['body_temp']:.1f}°C "
                f"TTL={ttl_remaining:.1f}s "
                f"Attack={attack_type}"
            )

            if count > 0 and packet_count >= count:
                print(f"\n[SIMULATOR] Completed deterministic run with {count} packets.")
                break

            time.sleep(send_interval)

    except KeyboardInterrupt:
        print("\n[SIMULATOR] Stopped.")
    finally:
        client.loop_stop()
        client.disconnect()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CADS IoMT Device Simulator")
    parser.add_argument(
        "--mode",
        choices=["normal", "tamper", "replay", "bad_sig", "c2", "anomaly", "gate2_normal", "gate2_bad_sig", "gate2_replay", "gate2_stale", "gate2_mba"],
        default="normal",
        help="Simulation mode"
    )
    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="Number of packets to send; 0 means run forever"
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Deterministic random seed for reproducible experiments"
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=SEND_INTERVAL,
        help="Seconds between packets"
    )
    args = parser.parse_args()
    run(args.mode, count=args.count, seed=args.seed, send_interval=args.interval)