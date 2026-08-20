import hashlib
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

import gate1.verify as gate1
import simulator.simulator as simulator


def _build_signed_packet(private_key, device_id="dev-001", ttl_offset_ms=120000):
    now_ms = time.time() * 1000
    ttl_expiry = now_ms + ttl_offset_ms
    payload_enc = b"test-payload"
    payload_hash = hashlib.sha256(payload_enc).hexdigest()

    packet = {
        "device_id": device_id,
        "device_name": "SIM-ECG-01",
        "session_key_enc": "enc-session-placeholder",
        "payload_enc": payload_enc.hex(),
        "ttl_expiry": ttl_expiry,
        "pop_chain": [{"hop_type": "DEVICE_ORIGIN"}],
        "payload_hash": payload_hash,
        "attack_type": "NONE",
        "sensor_data": {
            "heart_rate": 75.0,
            "body_temp": 36.9,
            "battery_level": 80.0,
            "signal_strength": 88.0,
        },
        "packet_timestamp": now_ms,
    }

    signing_input = (
        packet["device_id"] +
        packet["session_key_enc"] +
        str(packet["ttl_expiry"]) +
        packet["payload_hash"]
    ).encode()

    signature = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    packet["dbi_signature"] = signature.hex()
    return packet


def test_bce_allow_and_block(monkeypatch):
    monkeypatch.setattr(simulator, "log_bce_event", lambda *args, **kwargs: None)
    assert simulator.bce_check("localhost", 1883) is True
    assert simulator.bce_check("evil-c2.example", 4444) is False


def test_csm_packet_structure_check():
    private_key = ec.generate_private_key(ec.SECP256R1())
    packet = _build_signed_packet(private_key)
    assert gate1.check_csm_structure(packet) is True

    packet.pop("payload_hash")
    assert gate1.check_csm_structure(packet) is False


def test_dbi_signature_validation():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    packet = _build_signed_packet(private_key)

    assert gate1.verify_dbi_signature(packet, public_key) is True

    packet["dbi_signature"] = ("00" * 64)
    try:
        gate1.verify_dbi_signature(packet, public_key)
        assert False, "Expected invalid signature"
    except Exception:
        assert True


def test_cttl_validation():
    private_key = ec.generate_private_key(ec.SECP256R1())
    packet = _build_signed_packet(private_key, ttl_offset_ms=10000)

    ok, ttl_left = gate1.check_ttl_valid(packet, now_ms=packet["ttl_expiry"] - 5000)
    assert ok is True
    assert ttl_left > 0

    expired, ttl_left_expired = gate1.check_ttl_valid(packet, now_ms=packet["ttl_expiry"] + 1)
    assert expired is False
    assert ttl_left_expired <= 0


def test_popc_validation():
    private_key = ec.generate_private_key(ec.SECP256R1())
    packet = _build_signed_packet(private_key)

    ok, reason = gate1.check_popc_chain(packet)
    assert ok is True
    assert reason is None

    packet["pop_chain"] = []
    ok, reason = gate1.check_popc_chain(packet)
    assert ok is False
    assert reason == "POPC_MISSING"


def test_mba_anomaly_detection():
    normal = {
        "heart_rate": 80,
        "body_temp": 36.8,
        "battery_level": 75,
        "signal_strength": 85,
    }
    anomaly = {
        "heart_rate": 170,
        "body_temp": 39.5,
        "battery_level": 9,
        "signal_strength": 12,
    }

    assert gate1.check_mba(normal) is True
    assert gate1.check_mba(anomaly) is False


def test_run_gate1_accepts_valid_packet(monkeypatch):
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    packet = _build_signed_packet(private_key, device_id="known-device")

    monkeypatch.setattr(
        gate1,
        "get_device",
        lambda _device_id: ("known-device", "SIM-ECG-01", "ACTIVE", 0, 0, 0, None),
    )

    result = gate1.run_gate1(packet, public_key)
    assert result["gate1_pass"] is True
    assert result["check_csm"] is True
    assert result["check_mba"] is True
