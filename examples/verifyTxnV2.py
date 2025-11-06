import hashlib
from ecdsa import VerifyingKey, SECP256k1
from ecdsa.util import sigdecode_string
from signTxnV2 import canonical_tx_bytes, DEFAULT_CHAIN_ID

# Transaction to verify
transaction = {
    'sender': "Alice",
    'receiver': "Bob",
    'amount': 10,
    'nonce': 1 
}

# Signature and public key (from signing)
signature_hex = "98e6713990c62770ff3819b25975a6fd6df7aba50d5186914b74da4484e14f535ba71dd336e42f6f1b4a51fb2d9fdad5e6230f0f89e20b664a162378f27d94c8"
public_key_hex = "02dc617fef798db0ecf718152ab538bcd4bc2aee49c32bcfdcb386b67485189cd1"

print(f"Public Key (compressed hex): {public_key_hex}\n")
print(f"Signature (64 bytes r||s): {signature_hex}\n")

def verify_transaction(transaction, public_key_hex, signature_hex):
    try:
        # 1) Canonical encoding with domain separation (same as signing)
        tx_bytes = canonical_tx_bytes(transaction)
        message = b"TXN|v1|" + DEFAULT_CHAIN_ID + b"|" + tx_bytes
        
        # 2) Hash with SHA3-256 (same as signing)
        digest = hashlib.sha3_256(message).digest()
        
        # 3) Reconstruct verifying key from compressed public key hex
        public_key_bytes = bytes.fromhex(public_key_hex)
        verifying_key = VerifyingKey.from_string(
            public_key_bytes, 
            curve=SECP256k1
        )
        
        # 4) Convert signature hex to bytes
        signature_bytes = bytes.fromhex(signature_hex)
        
        # 5) Verify signature
        verifying_key.verify_digest(
            signature_bytes,
            digest,
            sigdecode=sigdecode_string
        )
        
        print("Signature verified successfully!")
        
    except Exception as e:
        print(f"Signature verification failed: {str(e)}")

verify_transaction(transaction, public_key_hex, signature_hex)
