from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Helper functions for generating keys and signing transactions
def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key().decode()
    public_key = key.publickey().export_key().decode()
    return private_key, public_key

def sign_transaction(private_key, transaction_data):
    key = RSA.import_key(private_key)
    hash_object = SHA256.new(transaction_data)
    signature = pkcs1_15.new(key).sign(hash_object)
    return signature

def verify_signature(public_key_str, transaction_data, signature_hex):
        try:
            print('Verifying signature...')
            public_key = RSA.import_key(public_key_str) # import public key
            hash_object = SHA256.new(transaction_data)  # create sha256 hash object
            signature = bytes.fromhex(signature_hex) # convert signature to bytes
            pkcs1_15.new(public_key).verify(hash_object, signature) # verify signature
            print('Signature verified successfully')

            return True
        except (ValueError, TypeError) as e:
            print(f'Signature verification failed: {str(e)}')
            return False   