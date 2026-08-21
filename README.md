CADS - Credential-Agnostic Data Sovereignty

CADS is a zero-trust, data-centric security framework for IoMT environments.
The security boundary is the data packet itself, not user credentials or network perimeter assumptions.

Implemented Algorithms (All 6)
- DBI (Device-Bound Identity): ECC signature authenticity per packet.
- C-TTL (Cryptographic Time-to-Live): packet-level expiry enforcement.
- BCE (Behavioral Contract Engine): structural outbound allowlist enforcement.
- PoPC (Proof-of-Path Chain): origin/path metadata integrity checks.
- CSM (Cryptographic State Machine): fail-closed packet-structure and sequence validation.
- MBA (Mutual Behavioral Attestation): physiological and device-behavior anomaly screening.

Architecture
- simulator/: device-side packet generation and attack simulation.
- gate1/: Gate 1 verification and security decisioning.
- gate2/: Gate 2 challenge-response authentication, ECDH session setup, and MBA attestation.
- database/: SQLite schema and seed data.
- dashboard/: SOC + reviewer evaluation dashboard.
- tools/: local MQTT broker launcher.

Quick Start
1. Generate keys and the device registry:
   python keys/key.py

2. Initialize database and schema:
   python database/init_db.py

3. Start the local MQTT broker:
   python tools/mqtt_broker.py

4. Start Gate 1 verifier:
   python gate1/verify.py

5. Start dashboard:
   streamlit run dashboard/SOC.py

6. In another terminal, run deterministic scenarios:
   python simulator/simulator.py --mode normal --count 25 --seed 11 --interval 0.6
   python simulator/simulator.py --mode tamper --count 20 --seed 12 --interval 0.6
   python simulator/simulator.py --mode replay --count 20 --seed 13 --interval 0.6
   python simulator/simulator.py --mode bad_sig --count 20 --seed 14 --interval 0.6
   python simulator/simulator.py --mode anomaly --count 20 --seed 15 --interval 0.6
   python simulator/simulator.py --mode c2
   python simulator/simulator.py --mode gate2_normal
   python simulator/simulator.py --mode gate2_bad_sig
   python simulator/simulator.py --mode gate2_replay
   python simulator/simulator.py --mode gate2_stale
   python simulator/simulator.py --mode gate2_mba

Evaluation Dashboard
The dashboard includes:
- Measurable results: packet counts, confusion matrix, pass/reject summaries, trend graphs.
- Reproducible experiments: fixed scenario table and deterministic simulator commands.
- Baseline comparison: signature-only baseline vs full CADS pipeline.
- Performance metrics: verification latency mean/p95 and end-to-end latency.
  <img width="1846" height="941" alt="Screenshot 2026-08-20 232342" src="https://github.com/user-attachments/assets/5f8fb02d-f586-4a50-be37-d3f0d3da4614" />
  
  <img width="1860" height="549" alt="Screenshot 2026-08-20 232443" src="https://github.com/user-attachments/assets/0073d909-0f6c-4ce3-9352-ace4083aaaaf" />
  
  <img width="1658" height="588" alt="Screenshot 2026-08-20 232457" src="https://github.com/user-attachments/assets/336b246c-db45-417f-8294-4aa756060c67" />



Implementation Process
1. Device provisioning creates ECC P-256 device/cloud keys and a device registry entry.
2. The simulator creates signed, encrypted telemetry packets with a C-TTL expiry, payload hash, and PoPC origin record.
3. Gate 1 validates packet structure (CSM), device registration, DBI signature, C-TTL, payload hash, PoPC, and sensor MBA checks.
4. Gate 2 issues a single-use nonce. The device signs the nonce and timestamp with ECDSA P-256; the gate verifies it against the registered public key or certificate.
5. After signature verification, both sides use ephemeral ECDH P-256 and HKDF to derive a session key. Only a short session key ID is logged.
6. Gate 2 applies the behavioral model, rejects stale/replayed challenges, and keeps first-seen devices provisional until enough samples exist.
7. BCE records allowed and blocked network destinations. The SOC portal reads the SQLite evidence store and refreshes live.
8. Real ESP32 integration should publish the same packet fields and gate event schema; the cryptographic checks remain the same, while device-specific sensor ranges and registry data become configuration.

Technology Stack
- Python 3 with `cryptography` for ECDSA P-256, ECDH, HKDF, AES-GCM, hashing, and certificate parsing.
- Paho MQTT for local broker/device messaging.
- SQLite for deterministic local evidence, alerts, gate decisions, network telemetry, and audit records.
- Streamlit with HTML/CSS panels for the live SOC portal and CADS Evaluation view.
- Pandas for metrics, pass rates, latency summaries, and behavioral trend preparation.
- Pytest for algorithm and Gate-2 regression tests.

Encryption and Integrity Details
- DBI: each telemetry header is signed with the device private key; Gate 1 verifies with the registered public key.
- ECDSA: authenticates the Gate-2 response. It does not encrypt data.
- ECDH: creates a shared secret without sending the session key over MQTT.
- HKDF-SHA256: turns the ECDH shared secret into a 32-byte session key.
- AES-256-GCM: encrypts telemetry payloads and detects ciphertext tampering.
- SHA-256: records payload hashes and shortened, non-secret session key IDs.
- C-TTL: expires session/packet cryptographic material and requires rotation.
- Nonces and timestamps: make each Gate-2 challenge single-use and time-bounded.
- Certificates: Gate 2 can verify a registered PEM certificate's public key; private keys are never displayed or logged.

Hardware Integration Contract
- ESP32 must provide a stable `device_id`, device public key/certificate, ECDSA signature, timestamp, nonce response, ephemeral ECDH public key, encrypted payload, payload hash, TTL expiry, and PoPC chain.
- The ESP32 should publish Gate-2 responses separately from telemetry so replay, timeout, and signature failures are auditable.
- The current simulator is a protocol test source, not a substitute for hardware calibration. Production MBA thresholds must be learned from validated device baselines.

Run Tests (All Algorithms)
- pytest -q tests/test_algorithms.py

Reset from scratch
- Delete database/cads.db
- Re-run:
  - python keys/key.py
  - python database/init_db.py
