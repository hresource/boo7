# generate_key.py
# ------------------------------------------------------------
# 1. Run this once on the target PC
# 2. It prints:
#      • the full license key
#      • ready-to-paste JSON for Vercel data/allowed.json
# ------------------------------------------------------------

import json, base64, rsa, hashlib, os
from datetime import datetime

# ------------------------------------------------------------
# AUTOMATIC PC NAME (same logic as b007.py)
# ------------------------------------------------------------
PC_NAME = os.environ.get("COMPUTERNAME", "UNKNOWN-PC")
if not PC_NAME or PC_NAME == "UNKNOWN-PC":
    raise RuntimeError("COMPUTERNAME environment variable not found!")

# ------------------------------------------------------------
# EXPIRY – change once (ISO format)
# ------------------------------------------------------------
EXPIRY = "2026-12-31T23:59:59"   # <-- edit if you want a different date

# ------------------------------------------------------------
# Load private key (must be in same folder)
# ------------------------------------------------------------
try:
    with open("private_key.pem", "rb") as f:
        priv = rsa.PrivateKey.load_pkcs1(f.read())
except FileNotFoundError:
    raise FileNotFoundError("private_key.pem not found in current folder!")

# ------------------------------------------------------------
# Build payload (must match b007.py validation)
# ------------------------------------------------------------
machine_id = hashlib.sha256(PC_NAME.encode()).hexdigest()[:16]

payload = {
    "expiry": EXPIRY,
    "machine": machine_id,
    "type": "lifetime"
}
payload_b = json.dumps(payload).encode()

# ------------------------------------------------------------
# Sign with RSA-SHA256
# ------------------------------------------------------------
sig = rsa.sign(payload_b, priv, "SHA-256")
license_key = base64.b64encode(payload_b + b"|" + sig).decode()

# ------------------------------------------------------------
# Compute SHA-256 hash of the full key (for Vercel)
# ------------------------------------------------------------
key_hash = hashlib.sha256(license_key.encode()).hexdigest()

# ------------------------------------------------------------
# OUTPUT
# ------------------------------------------------------------
print("\n" + "="*60)
print("B007 LICENSE KEY (copy & paste when prompted):")
print(license_key)
print("\n" + "="*60)
print("ADD THIS TO Vercel data/allowed.json :")
print(json.dumps({
    "hashes": [key_hash],
    "keys": {
        key_hash: {
            "expiry": EXPIRY,
            "machine": machine_id
        }
    }
}, indent=4))
print("="*60 + "\n")