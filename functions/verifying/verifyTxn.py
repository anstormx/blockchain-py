import json
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Constants
signature_hex = "7f5e766d15b500cd82bd75df269bb481e2c46aa7dfcb41362c4d17f1ecd5fee426beae727603e024145180a82d4a70cff9a324fa3707428dcf6f30ff75e088fd0b923bf3e1e3e1cf6d10364bca3ef587be0c6030c604a5aefd3906d22f835c500aaa82ec907b4a4adc6ca1ef213662cc9090af7eb4670e4eadab885d808260a1fce22eed9a922728613ae0bae11a44a59f9aa1fa2a99542ca0acde877e7592270ca4843ed9e9d91bd4ad63656155d999749c1f81c5f6c5fcfb9f96fa66c25ac62f7f1c857842e02b39048e9484ae2f9b48244cddba539d96268862f5f83195bb291ecd8dd0717212c4de2633cb00b19465eb86cbd2f5c8a6bd90a0f1f9aae535"
public_key_str = """-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1UktazHclHqtQ679wcmy\nm1ov7T6cvrRwkkfXFkrDggaW/thNnm7TkAI3lPh2N+trB2oFNQ8IQpvgRfxvckrP\njGyPuKQk3u2b+bOa85gTgYULW7obR4VBo1p2KlKyzc9lIzzDSSpb9pBwIwJeabN7\nIvTs1sMU/Tlm5oyFn6qHRVeGzManP2jhExkrjreTiCKiIsN2hsWxZaEAbx0uHft6\npQ6SjQKe4hLRBW4TRkXF0wKeSINVHZVK4wuLWPHZ/d+L54rpXwEzA+gouMzaQ8qO\nBFmw2m97NxUQOgRk5iGiMxA2Qz8hBxZICCVFNaT8xKuiD+eYUzERtG2H2KQzxbv+\n0wIDAQAB\n-----END PUBLIC KEY-----"""
# Example transaction
transaction = {
    "sender": "Alice",
    "receiver": "Bob",
    "amount": 10,
    "nonce": 1
}

# Verify transaction function
def verify_transaction(transaction, public_key_str, signature_hex):
    try:
        print(f'Public key: {public_key_str} \n')
        print(f'Signature: {signature_hex}\n')
        public_key = RSA.import_key(public_key_str)
        transaction_data = json.dumps(transaction, sort_keys=True).encode() # convert transaction to JSON string and encode it
        hash_object = SHA256.new(transaction_data) # create SHA256 hash object
        signature = bytes.fromhex(signature_hex) # convert signature to bytes
        pkcs1_15.new(public_key).verify(hash_object, signature) # verify signature
        
        print("Signature verified successfully!")
        return True

    except Exception as e:
        print(f"Signature verification failed: {str(e)}")
        return False

verify_transaction(transaction, public_key_str, signature_hex)
