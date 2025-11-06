import json
import os
import hmac
import hashlib
from math import ceil
from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError
from ecdsa.util import sigencode_string, sigdecode_string

# ============================================================================
# SHA-3 Based Cryptography for Blockchain (secp256k1)
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
    Uses deterministic JSON with no whitespace
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
    Uses pure HKDF(SHA3-256) with domain separation
    """
    entropy = os.urandom(32)
    
    prk_a = hkdf_extract_sha3(salt=b"KEYGEN|v1", ikm=entropy)
    seed_a = hkdf_expand_sha3(prk_a, info=f"SEED|{app_name}".encode(), length=32)
    
    if passphrase is None:
        return seed_a
    
    prk_b = hkdf_extract_sha3(salt=seed_a, ikm=passphrase)
    return hkdf_expand_sha3(prk_b, info=b"PASSPHRASE|v1", length=32)

def reduce_to_scalar(okm: bytes, n_curve: int, info_ctx: bytes, prk: bytes) -> int:
    """
    Rejection sampling to convert bytes to valid curve scalar
    With 32 bytes for secp256k1, acceptance probability ≈ 1.0
    """
    L = len(okm)
    k = int.from_bytes(okm, "big")
    attempt = 0
    
    while True:
        if 1 <= k < n_curve:
            return k
        
        attempt += 1
        info_retry = info_ctx + f"|retry:{attempt}".encode()
        okm = hkdf_expand_sha3(prk, info_retry, L)
        k = int.from_bytes(okm, "big")

def curve_master_key(master_seed: bytes, curve_id: str, n_curve: int) -> tuple:
    """
    Derive curve-specific master private key with chain code (BIP32-style)
    Returns: (private_key_int, chain_code_bytes)
    """
    salt = f"MASTER|{curve_id}".encode()
    prk = hkdf_extract_sha3(salt=salt, ikm=master_seed)
    
    info = f"MASTER_SK|{curve_id}".encode()
    okm = hkdf_expand_sha3(prk, info=info, length=64)
    
    sk = reduce_to_scalar(okm[:32], n_curve, info, prk)
    chain_code = okm[32:]
    
    return sk, chain_code

def child_key(parent_sk: int, chain_code: bytes, curve_id: str, 
               path_index: int, n_curve: int, hardened: bool = True) -> tuple:
    """
    Derive hierarchical child key with chain code (BIP32-style)
    Returns: (child_private_key_int, child_chain_code_bytes)
    """
    derivation_type = b"HARD" if hardened else b"SOFT"
    
    parent_bytes = parent_sk.to_bytes(32, "big")
    index_bytes = path_index.to_bytes(4, "big")
    data = derivation_type + b"|" + parent_bytes + b"|" + index_bytes
    
    salt = f"CHILD|{curve_id}".encode()
    prk = hkdf_extract_sha3(salt=salt, ikm=chain_code + data)
    
    info = b"PATH:" + derivation_type + b"|" + index_bytes
    okm = hkdf_expand_sha3(prk, info=info, length=64)
    
    sk = reduce_to_scalar(okm[:32], n_curve, info, prk)
    child_chain_code = okm[32:]
    
    return sk, child_chain_code

# ============================================================================
# Public API Functions (compatible with blockchain.py and app.py)
# ============================================================================

def generate_keys(app_name: str = "blockchain-py", 
                  derivation_indices: list = None) -> tuple:
    """
    Generate secp256k1 key pair using SHA-3 based derivation
    
    Args:
        app_name: Application name for domain separation
        derivation_indices: Optional list of child indices (e.g., [44, 0, 0, 0])
    
    Returns:
        tuple: (private_key_hex, public_key_hex)
        - private_key_hex: 64-char hex string (32 bytes)
        - public_key_hex: 66-char hex string (33 bytes compressed)
    """
    # Generate master seed
    master_seed = make_master_seed(app_name, passphrase=None)
    
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
    
    # Return private key as hex
    private_key_hex = sk_bytes.hex()
    
    return private_key_hex, public_key_hex

def sign_transaction(private_key_hex: str, transaction_data: bytes, 
                     chain_id: bytes = DEFAULT_CHAIN_ID) -> bytes:
    """
    Sign transaction using deterministic ECDSA (RFC 6979) with low-S normalization
    
    Args:
        private_key_hex: Private key as hex string (64 chars = 32 bytes)
        transaction_data: Transaction data as bytes (typically JSON encoded)
        chain_id: Chain identifier for domain separation
    
    Returns:
        Signature as bytes (64 bytes: r||s with low-S)
    """
    # Parse transaction data if it's JSON
    try:
        transaction = json.loads(transaction_data.decode())
        tx_bytes = canonical_tx_bytes(transaction)
    except:
        # If not JSON, use raw bytes
        tx_bytes = transaction_data
    
    # Domain-separated message
    message = b"TXN|v1|" + chain_id + b"|" + tx_bytes
    
    # Hash with SHA3-256
    digest = hashlib.sha3_256(message).digest()
    
    # Reconstruct signing key from hex
    private_key_bytes = bytes.fromhex(private_key_hex)
    signing_key = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    
    # RFC 6979 deterministic signing
    signature = signing_key.sign_digest_deterministic(
        digest,
        hashfunc=hashlib.sha3_256,
        sigencode=sigencode_string,
    )
    
    # Low-S normalization
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    
    if s > SECP256K1_ORDER // 2:
        s = SECP256K1_ORDER - s
    
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")

def verify_signature(public_key_hex: str, transaction_data: bytes, 
                     signature_hex: str, chain_id: bytes = DEFAULT_CHAIN_ID) -> bool:
    """
    Verify secp256k1 signature with SHA3-256
    
    Args:
        public_key_hex: Public key as hex string (compressed, 66 chars = 33 bytes)
        transaction_data: Transaction data as bytes
        signature_hex: Signature as hex string (128 chars = 64 bytes)
        chain_id: Chain identifier for domain separation
    
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        print('Verifying signature...')
        
        # Parse transaction data if it's JSON
        try:
            transaction = json.loads(transaction_data.decode())
            tx_bytes = canonical_tx_bytes(transaction)
        except:
            tx_bytes = transaction_data
        
        # Domain-separated message
        message = b"TXN|v1|" + chain_id + b"|" + tx_bytes
        
        # Hash with SHA3-256
        digest = hashlib.sha3_256(message).digest()
        
        # Reconstruct verifying key from hex
        public_key_bytes = bytes.fromhex(public_key_hex)
        verifying_key = VerifyingKey.from_string(
            public_key_bytes, 
            curve=SECP256k1
        )
        
        # Convert signature hex to bytes
        signature_bytes = bytes.fromhex(signature_hex)
        
        # Verify signature
        verifying_key.verify_digest(
            signature_bytes,
            digest,
            sigdecode=sigdecode_string
        )
        
        print('Signature verified successfully')
        return True
        
    except (BadSignatureError, ValueError, TypeError) as e:
        print(f'Signature verification failed: {str(e)}')
        return False

# ============================================================================
# Advanced Functions (optional, for more control)
# ============================================================================

def generate_keys_with_chain_code(app_name: str = "blockchain-py",
                                  derivation_indices: list = None) -> tuple:
    """
    Generate keys with chain code for further derivation
    
    Returns:
        tuple: (private_key_hex, public_key_hex, chain_code_hex)
    """
    master_seed = make_master_seed(app_name, passphrase=None)
    sk, chain_code = curve_master_key(master_seed, "secp256k1", SECP256K1_ORDER)
    
    if derivation_indices:
        for index in derivation_indices:
            sk, chain_code = child_key(
                sk, chain_code, "secp256k1", index, SECP256K1_ORDER, hardened=True
            )
    
    sk_bytes = sk.to_bytes(32, "big")
    signing_key = SigningKey.from_string(sk_bytes, curve=SECP256k1)
    verifying_key = signing_key.get_verifying_key()
    
    private_key_hex = sk_bytes.hex()
    public_key_hex = verifying_key.to_string("compressed").hex()
    chain_code_hex = chain_code.hex()
    
    return private_key_hex, public_key_hex, chain_code_hex

def derive_child_from_parent(parent_private_key_hex: str, 
                            parent_chain_code_hex: str,
                            child_index: int) -> tuple:
    """
    Derive a child key from parent key and chain code
    
    Returns:
        tuple: (child_private_key_hex, child_public_key_hex, child_chain_code_hex)
    """
    parent_sk = int.from_bytes(bytes.fromhex(parent_private_key_hex), "big")
    parent_chain_code = bytes.fromhex(parent_chain_code_hex)
    
    child_sk, child_chain_code = child_key(
        parent_sk, parent_chain_code, "secp256k1", 
        child_index, SECP256K1_ORDER, hardened=True
    )
    
    child_sk_bytes = child_sk.to_bytes(32, "big")
    signing_key = SigningKey.from_string(child_sk_bytes, curve=SECP256k1)
    verifying_key = signing_key.get_verifying_key()
    
    return (
        child_sk_bytes.hex(),
        verifying_key.to_string("compressed").hex(),
        child_chain_code.hex()
    )
