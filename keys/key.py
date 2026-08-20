"""
CADS Demo — Key Generation
Run this ONCE before starting the demo.
Generates:
  - Device DBI key pair  (simulates keys burned into TrustZone-M at manufacture)
  - Cloud key pair       (simulates cloud backend keys)
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import os
import hashlib
import json

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))

def generate_keypair(name):
    # Generate ECC P-256 key pair (same curve used in real CADS firmware)
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key  = private_key.public_key()

    # Serialize private key to PEM
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize public key to PEM
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Save files
    priv_path = os.path.join(OUTPUT_DIR, f"{name}_private.pem")
    pub_path  = os.path.join(OUTPUT_DIR, f"{name}_public.pem")

    with open(priv_path, "wb") as f:
        f.write(private_pem)
    with open(pub_path, "wb") as f:
        f.write(public_pem)

    print(f"[✓] {name} private key → {priv_path}")
    print(f"[✓] {name} public key  → {pub_path}")

    return public_pem


def generate_device_id(public_pem):
    # device_id = SHA-256 of the public key (exactly as in CADS spec)
    device_id = hashlib.sha256(public_pem).hexdigest()[:32]
    return device_id


if __name__ == "__main__":
    print("\n=== CADS Key Generation ===\n")

    # Generate device keys (simulates TrustZone-M manufacture provisioning)
    print("--- Device DBI Key Pair ---")
    device_pub_pem = generate_keypair("device")
    device_id = generate_device_id(device_pub_pem)
    print(f"[✓] device_id (SHA-256 of public key) = {device_id}\n")

    # Generate cloud keys
    print("--- Cloud Key Pair ---")
    generate_keypair("cloud")

    # Save device registry entry
    # In real CADS this is done at manufacture and sent to cloud registry
    registry = {
        "device_id":   device_id,
        "device_name": "SIM-ECG-01",
        "status":      "ACTIVE",
        "threat_score": 0,
        "expected_path": ["gateway-SW-01", "gateway-SW-02"],
    }

    reg_path = os.path.join(OUTPUT_DIR, "device_registry.json")
    with open(reg_path, "w") as f:
        json.dump(registry, f, indent=2)

    print(f"\n[✓] Device registry entry → {reg_path}")
    print("\n=== Done. Keys ready. Run the demo. ===\n")
    