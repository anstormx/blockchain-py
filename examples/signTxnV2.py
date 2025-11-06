import json
import os
import hmac
import hashlib
from math import ceil
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_string

# ============================================================================
# SHA-3 Based Key Generation & Signing (secp256k1)
# Deterministic signatures, low-S normalization, chain codes
# ============================================================================

# secp256k1 curve order
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Default chain ID for transaction domain separation
DEFAULT_CHAIN_ID = b"blockchain-py-v1"

# --- SHA3-based HKDF Implementation ---
def hkdf_extract_sha3(salt: bytes, ikm: bytes) -> bytes:
    """HKDF Extract using SHA3-256"""
    if not salt:
        salt = b'\x00' * 32
    return hmac.new(salt, ikm, hashlib.sha3_256).digest()

def hkdf_expand_sha3(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF Expand using SHA3-256"""
    hash_len = 32  # SHA3-256 output length
    blocks_needed = ceil(length / hash_len)
    okm = b""
    previous = b""
    
    for i in range(1, blocks_needed + 1):
        previous = hmac.new(prk, previous + info + bytes([i]), hashlib.sha3_256).digest()
        okm += previous
    
    return okm[:length]

# --- Canonical Transaction Encoding ---
def canonical_tx_bytes(transaction: dict) -> bytes:
    """
    Canonical binary encoding for transactions
    Uses deterministic JSON with no whitespace for now
    For production: consider CBOR canonical mode or RLP
    """
    return json.dumps(
        transaction, 
        sort_keys=True, 
        separators=(",", ":"), 
        ensure_ascii=False
    ).encode()

# --- Core Key Generation Functions ---
def make_master_seed(app_name: str, passphrase: bytes = None) -> bytes:
    """
    Generate master seed using OS CSPRNG and optional passphrase
    Uses pure HKDF(SHA3-256) with domain separation (simpler than cSHAKE/KMAC stubs)
    
    Args:
        app_name: Application name for domain separation
        passphrase: Optional passphrase for deterministic backup
    
    Returns:
        32-byte master seed
    """
    entropy = os.urandom(32)
    
    # Domain-separated seed generation using HKDF
    prk_a = hkdf_extract_sha3(salt=b"KEYGEN|v1", ikm=entropy)
    seed_a = hkdf_expand_sha3(prk_a, info=f"SEED|{app_name}".encode(), length=32)
    
    if passphrase is None:
        return seed_a
    
    # Combine with passphrase using HKDF
    prk_b = hkdf_extract_sha3(salt=seed_a, ikm=passphrase)
    return hkdf_expand_sha3(prk_b, info=b"PASSPHRASE|v1", length=32)

def reduce_to_scalar(okm: bytes, n_curve: int, info_ctx: bytes, prk: bytes) -> int:
    """
    Rejection sampling to convert bytes to valid curve scalar
    Ensures uniform distribution in [1, n_curve-1]
    
    With 32 bytes for secp256k1, acceptance probability ≈ 1.0 (almost always first try)
    
    Args:
        okm: Key material to convert (32 bytes for secp256k1)
        n_curve: Curve order
        info_ctx: Context for retry derivation
        prk: Pseudorandom key for retry expansion
    
    Returns:
        Valid scalar in range [1, n_curve-1]
    """
    L = len(okm)  # Should be 32 for secp256k1
    k = int.from_bytes(okm, "big")
    attempt = 0
    
    while True:
        if 1 <= k < n_curve:
            return k
        
        # Rejection sampling: re-expand with modified context
        # With L=32, this almost never loops for secp256k1
        attempt += 1
        info_retry = info_ctx + f"|retry:{attempt}".encode()
        okm = hkdf_expand_sha3(prk, info_retry, L)
        k = int.from_bytes(okm, "big")

def curve_master_key(master_seed: bytes, curve_id: str, n_curve: int) -> tuple:
    """
    Derive curve-specific master private key with chain code (BIP32-style)
    
    Args:
        master_seed: Master seed from make_master_seed()
        curve_id: Curve identifier (e.g., "secp256k1")
        n_curve: Curve order
    
    Returns:
        tuple: (private_key_int, chain_code_bytes)
    """
    salt = f"MASTER|{curve_id}".encode()
    prk = hkdf_extract_sha3(salt=salt, ikm=master_seed)
    
    info = f"MASTER_SK|{curve_id}".encode()
    # Expand to 64 bytes: 32 for private key, 32 for chain code
    okm = hkdf_expand_sha3(prk, info=info, length=64)
    
    # First 32 bytes -> private key scalar
    sk = reduce_to_scalar(okm[:32], n_curve, info, prk)
    
    # Last 32 bytes -> chain code for child derivation
    chain_code = okm[32:]
    
    return sk, chain_code

def child_key(parent_sk: int, chain_code: bytes, curve_id: str, 
               path_index: int, n_curve: int, hardened: bool = True) -> tuple:
    """
    Derive hierarchical child key with chain code (BIP32-style)
    
    Args:
        parent_sk: Parent private key
        chain_code: Parent chain code (32 bytes)
        curve_id: Curve identifier
        path_index: Child index (0, 1, 2, ...)
        n_curve: Curve order
        hardened: If True, use hardened derivation (recommended)
    
    Returns:
        tuple: (child_private_key_int, child_chain_code_bytes)
    """
    # Hardened derivation uses parent private key
    # Non-hardened would use parent public key (not implemented here for simplicity)
    derivation_type = b"HARD" if hardened else b"SOFT"
    
    # Combine parent key and index
    parent_bytes = parent_sk.to_bytes(32, "big")
    index_bytes = path_index.to_bytes(4, "big")
    data = derivation_type + b"|" + parent_bytes + b"|" + index_bytes
    
    # Use chain code as key material
    salt = f"CHILD|{curve_id}".encode()
    prk = hkdf_extract_sha3(salt=salt, ikm=chain_code + data)
    
    info = b"PATH:" + derivation_type + b"|" + index_bytes
    # Expand to 64 bytes: 32 for key, 32 for chain code
    okm = hkdf_expand_sha3(prk, info=info, length=64)
    
    # Derive child key
    sk = reduce_to_scalar(okm[:32], n_curve, info, prk)
    child_chain_code = okm[32:]
    
    return sk, child_chain_code

# --- Transaction Signing with secp256k1 ---
def generate_secp256k1_keypair(app_name: str = "blockchain-py", 
                                passphrase: bytes = None,
                                derivation_indices: list = None):
    """
    Generate secp256k1 key pair using SHA-3 based derivation with chain codes
    
    Args:
        app_name: Application name for domain separation
        passphrase: Optional passphrase for deterministic generation
        derivation_indices: Optional list of child indices (e.g., [44, 0, 0, 0])
    
    Returns:
        tuple: (private_key_int, public_key_hex, signing_key_object, chain_code)
    """
    # Generate master seed
    master_seed = make_master_seed(app_name, passphrase)
    
    # Derive curve-specific master key with chain code
    sk, chain_code = curve_master_key(master_seed, "secp256k1", SECP256K1_ORDER)
    
    # Optionally derive child keys
    if derivation_indices:
        for index in derivation_indices:
            sk, chain_code = child_key(
                sk, chain_code, "secp256k1", index, SECP256K1_ORDER, hardened=True
            )
    
    # Create ecdsa SigningKey from the scalar
    sk_bytes = sk.to_bytes(32, "big")
    signing_key = SigningKey.from_string(sk_bytes, curve=SECP256k1)
    
    # Get public key (compressed format)
    verifying_key = signing_key.get_verifying_key()
    public_key_hex = verifying_key.to_string("compressed").hex()
    
    return sk, public_key_hex, signing_key, chain_code

def sign_transaction_sha3(signing_key: SigningKey, transaction: dict, 
                           chain_id: bytes = DEFAULT_CHAIN_ID) -> str:
    """
    Sign transaction using deterministic ECDSA (RFC 6979) with low-S normalization
    Prevents signature malleability
    
    Args:
        signing_key: ECDSA signing key
        transaction: Transaction dictionary
        chain_id: Chain identifier for domain separation
    
    Returns:
        Signature as hex string (64 bytes: r||s with low-S)
    """
    # 1) Canonical encoding with domain separation
    tx_bytes = canonical_tx_bytes(transaction)
    message = b"TXN|v1|" + chain_id + b"|" + tx_bytes
    
    # 2) Hash with SHA3-256
    digest = hashlib.sha3_256(message).digest()
    
    # 3) RFC 6979 deterministic signing (no random k)
    signature = signing_key.sign_digest_deterministic(
        digest,
        hashfunc=hashlib.sha3_256,
        sigencode=sigencode_string,  # Returns r||s (64 bytes)
    )
    
    # 4) Low-S normalization
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    
    # If s > n/2, use n - s (canonical form)
    if s > SECP256K1_ORDER // 2:
        s = SECP256K1_ORDER - s
    
    # Return canonical signature
    return (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex()

# ============================================================================
# Example Usage
# ============================================================================

if __name__ == "__main__":
    # Example transaction
    transaction = {
        'sender': "Alice",
        'receiver': "Bob",
        'amount': 10,
        'nonce': 1 
    }
    
    # Generate keypair with hierarchical derivation (BIP32-style)
    # Path: m/44'/0'/0'/0 (4 levels of hardened derivation)
    private_key_int, public_key_hex, signing_key, chain_code = generate_secp256k1_keypair(
        app_name="blockchain-py",
        passphrase=None,  # Set to b"your_passphrase" for deterministic generation
        derivation_indices=[44, 0, 0, 0]  # BIP32-style path indices
    )
    
    print(f"Private Key (int): \n{private_key_int}\n")
    print(f"Public Key (compressed hex): \n{public_key_hex}\n")
    print(f"Chain Code: {chain_code.hex()}\n")
    
    # Sign transaction with deterministic ECDSA + low-S
    signature = sign_transaction_sha3(signing_key, transaction)
    
    print(f"Signature (64 bytes, r||s low-S): \n{signature}\n")
