import sqlite3
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec

from gate2.verify import Gate2Authenticator, build_response


def _authenticator(tmp_path, **kwargs):
    return Gate2Authenticator(db_path=str(tmp_path / "gate2.db"), **kwargs)


def test_gate2_validates_signature_derives_session_and_promotes_trust(tmp_path):
    device_private = ec.generate_private_key(ec.SECP256R1())
    gate = _authenticator(tmp_path, min_full_samples=2)
    behavior = {"sequence": ["nonce", "signature", "ephemeral-key"], "timestamp_ms": int(time.time() * 1000)}
    gate.set_baseline("dev-001", {"sequence": behavior["sequence"]})

    first = gate.issue_challenge("dev-001", gate1_session_id="gate1-a", provisional=True)
    response, _ = build_response(device_private, first, behavior)
    result = gate.authenticate(response, device_private.public_key(), behavior)
    assert result["result"] == "PASS"
    assert result["gate_name"] == "gate2_auth"
    assert result["session_key_id"]
    assert result["gateway_ephemeral_public_key"]
    assert result["trust"] == "PROVISIONAL"

    second = gate.issue_challenge("dev-001", gate1_session_id="gate1-b")
    response, _ = build_response(device_private, second, behavior)
    assert gate.authenticate(response, device_private.public_key(), behavior)["trust"] == "FULL"

    with sqlite3.connect(gate.db_path) as conn:
        row = conn.execute("SELECT device_id, gate_name, result, session_key_id, reason FROM gate2_auth_logs").fetchall()
    assert len(row) == 2
    assert row[0][0:3] == ("dev-001", "gate2_auth", "PASS")


def test_gate2_consumes_nonce_after_bad_signature(tmp_path):
    device_private = ec.generate_private_key(ec.SECP256R1())
    gate = _authenticator(tmp_path)
    challenge = gate.issue_challenge("dev-001", gate1_session_id="gate1-a")
    response, _ = build_response(device_private, challenge)
    response["signature"] = "00"

    failed = gate.authenticate(response, device_private.public_key())
    assert failed["result"] == "FAIL"
    assert failed["reason"] == "BAD_SIGNATURE"
    replay = gate.authenticate(response, device_private.public_key())
    assert replay["reason"] == "NONCE_INVALID_OR_REPLAYED"


def test_gate2_rejects_stale_response_and_mba_anomaly(tmp_path):
    device_private = ec.generate_private_key(ec.SECP256R1())
    gate = _authenticator(tmp_path, window_seconds=2)
    challenge = gate.issue_challenge("dev-001", gate1_session_id="gate1-a")
    response, _ = build_response(device_private, challenge)
    response["timestamp_ms"] -= 10_000
    assert gate.authenticate(response, device_private.public_key())["reason"] == "RESPONSE_OUTSIDE_WINDOW"

    challenge = gate.issue_challenge("dev-001", gate1_session_id="gate1-b")
    gate.set_baseline("dev-001", {"ranges": {"auth_latency_ms": [0, 100]}})
    response, _ = build_response(device_private, challenge, {"auth_latency_ms": 900})
    result = gate.authenticate(response, device_private.public_key(), response["behavior"])
    assert result["reason"] == "MBA_ANOMALY"