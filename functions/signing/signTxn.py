import json
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Example transaction
transaction = {
    'sender': "Alice",
    'receiver': "Bob",
    'amount': 10,
    'nonce': 1 
}

def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key().decode()
    public_key = key.publickey().export_key().decode()
    return private_key, public_key

private_key, public_key = generate_keys()
transaction_data = json.dumps(transaction, sort_keys=True).encode()
hash_object = SHA256.new(transaction_data)
private_key_obj = RSA.import_key(private_key)
signature = pkcs1_15.new(private_key_obj).sign(hash_object)

print(f"Private Key: \n{private_key}\n")
print(f"Public Key: \n{public_key}\n")
print(f"Signature: \n{signature.hex()}\n")
