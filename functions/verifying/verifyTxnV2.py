import hashlib
from ecdsa import VerifyingKey, SECP256k1
from ecdsa.util import sigdecode_string
from signTxnV2 import canonical_tx_bytes, DEFAULT_CHAIN_ID

# Transaction to verify
transaction = {
    'sender_address': "0322b9af9e48f7d4ab3ca11ade0c93b2bc1ca80abc20c97e96717bbff488002dc6",
    'receiver_address': "03c116d12d88f3d32450c643ba706c7ff57dfdb3554078cff42c93535a5a592f23",
    'amount': 10,
    'nonce': 0
}

# Signature and public key (from signing)
signature_hex = "a5091313af9464e29f57004df5ac66283e10565d1203dcbd1361586b7f72a8e705c514845bb580b68d037edd3d19b045fc9e84819b9b9a957d4e6b5ea5eb0a0b"
public_key_hex = "0322b9af9e48f7d4ab3ca11ade0c93b2bc1ca80abc20c97e96717bbff488002dc6"

print(f"Public Key (compressed hex): {public_key_hex}\n")
print(f"Signature (64 bytes r||s): {signature_hex}\n")

def validate_address(address_hex: str) -> bool:
    """
    Validate that an address is a valid secp256k1 compressed public key
    
    Args:
        address_hex: Address as hex string (should be compressed public key)
    
    Returns:
        True if valid, False otherwise
    """
    try:
        # Check if valid hex string
        address_bytes = bytes.fromhex(address_hex)
        
        # Check length (33 bytes for compressed secp256k1 public key)
        if len(address_bytes) != 33:
            return False
        
        # Check prefix (02 or 03 for compressed keys)
        if address_bytes[0] not in (0x02, 0x03):
            return False
        
        # Try to parse as valid secp256k1 public key
        VerifyingKey.from_string(address_bytes, curve=SECP256k1)
        return True
        
    except (ValueError, TypeError):
        return False

def verify_transaction(transaction, public_key_hex, signature_hex):
    try:
        # 1) Validate sender address
        sender_address = transaction.get('sender_address')
        if not sender_address:
            print("Validation failed: Missing sender_address")
            return False
        
        if not validate_address(sender_address):
            print(f"Validation failed: Invalid sender_address format: {sender_address}")
            return False
        
        print(f"Sender address validated: {sender_address}")
        
        # 2) Validate receiver address
        receiver_address = transaction.get('receiver_address')
        if not receiver_address:
            print("Validation failed: Missing receiver_address")
            return False
        
        if not validate_address(receiver_address):
            print(f"Validation failed: Invalid receiver_address format: {receiver_address}")
            return False
        
        print(f"Receiver address validated: {receiver_address}")
        
        # 3) Verify sender_address matches the signing public key
        if sender_address != public_key_hex:
            print(f"Validation failed: sender_address doesn't match signing public key")
            print(f"   sender_address: {sender_address}")
            print(f"   public_key:     {public_key_hex}")
            return False
        
        print(f"Sender address matches signing public key")
        
        # 4) Canonical encoding with domain separation (same as signing)
        tx_bytes = canonical_tx_bytes(transaction)
        message = b"TXN|v1|" + DEFAULT_CHAIN_ID + b"|" + tx_bytes
        
        # 5) Hash with SHA3-256 (same as signing)
        digest = hashlib.sha3_256(message).digest()
        
        # 6) Reconstruct verifying key from compressed public key hex
        public_key_bytes = bytes.fromhex(public_key_hex)
        verifying_key = VerifyingKey.from_string(
            public_key_bytes, 
            curve=SECP256k1
        )
        
        # 7) Convert signature hex to bytes
        signature_bytes = bytes.fromhex(signature_hex)
        
        # 8) Verify signature
        verifying_key.verify_digest(
            signature_bytes,
            digest,
            sigdecode=sigdecode_string
        )
        
        print("Validation passed")
        return True
        
    except Exception as e:
        print(f"Validation failed: {str(e)}")
        return False

verify_transaction(transaction, public_key_hex, signature_hex)
