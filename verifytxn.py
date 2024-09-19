import json
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def verify_transaction(transaction, public_key_str, signature_hex):
    try:
        print(f'Public key: {public_key_str}')
        print(f'Transaction data: {transaction}')
        print(f'Signature: {signature_hex}...')
        public_key = RSA.import_key(public_key_str)

        transaction_data = json.dumps({
            "sender": transaction["sender"],
            "receiver": transaction["receiver"],
            "amount": transaction["amount"],
            "nonce": transaction["nonce"]
        }, sort_keys=True).encode()

        print(f'Transaction data: {transaction_data}...')

        h = SHA256.new(transaction_data)
        print(f'Hash: {h}...')

        signature = bytes.fromhex(signature_hex)
        print(f'Signature: {signature}...')

        pkcs1_15.new(public_key).verify(h, signature)
        print("Signature verification succeeded.")
        return True

    except (ValueError, TypeError) as e:
        print(f"Signature verification failed: {e}")
        return False

transaction = {
    "sender": "Alice",
    "receiver": "Bob",
    "amount": 10,
    "nonce": 1
}

signature_hex = "7f5e766d15b500cd82bd75df269bb481e2c46aa7dfcb41362c4d17f1ecd5fee426beae727603e024145180a82d4a70cff9a324fa3707428dcf6f30ff75e088fd0b923bf3e1e3e1cf6d10364bca3ef587be0c6030c604a5aefd3906d22f835c500aaa82ec907b4a4adc6ca1ef213662cc9090af7eb4670e4eadab885d808260a1fce22eed9a922728613ae0bae11a44a59f9aa1fa2a99542ca0acde877e7592270ca4843ed9e9d91bd4ad63656155d999749c1f81c5f6c5fcfb9f96fa66c25ac62f7f1c857842e02b39048e9484ae2f9b48244cddba539d96268862f5f83195bb291ecd8dd0717212c4de2633cb00b19465eb86cbd2f5c8a6bd90a0f1f9aae535"
public_key_str = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1UktazHclHqtQ679wcmy\nm1ov7T6cvrRwkkfXFkrDggaW/thNnm7TkAI3lPh2N+trB2oFNQ8IQpvgRfxvckrP\njGyPuKQk3u2b+bOa85gTgYULW7obR4VBo1p2KlKyzc9lIzzDSSpb9pBwIwJeabN7\nIvTs1sMU/Tlm5oyFn6qHRVeGzManP2jhExkrjreTiCKiIsN2hsWxZaEAbx0uHft6\npQ6SjQKe4hLRBW4TRkXF0wKeSINVHZVK4wuLWPHZ/d+L54rpXwEzA+gouMzaQ8qO\nBFmw2m97NxUQOgRk5iGiMxA2Qz8hBxZICCVFNaT8xKuiD+eYUzERtG2H2KQzxbv+\n0wIDAQAB\n-----END PUBLIC KEY-----"""

# "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1UktazHclHqtQ679wcmym1ov7T6cvrRwkkfXFkrDggaW/thN\nnm7TkAI3lPh2N+trB2oFNQ8IQpvgRfxvckrPjGyPuKQk3u2b+bOa85gTgYULW7ob\nR4VBo1p2KlKyzc9lIzzDSSpb9pBwIwJeabN7IvTs1sMU/Tlm5oyFn6qHRVeGzMan\nP2jhExkrjreTiCKiIsN2hsWxZaEAbx0uHft6pQ6SjQKe4hLRBW4TRkXF0wKeSINV\nHZVK4wuLWPHZ/d+L54rpXwEzA+gouMzaQ8qOBFmw2m97NxUQOgRk5iGiMxA2Qz8h\nBxZICCVFNaT8xKuiD+eYUzERtG2H2KQzxbv+0wIDAQABAoIBAE4kaGKMux8fLxnM\nJCZ6ylhGm6aVOQJZw6Ckd3YwYB7kYS/vecihHBv34/tNaKqmMulde5jr7//PckTR\n7tb198KgB6wDX4rZjTrYBd5XilX6s6WgstvqQ5kgzIhHEkF7Sbe2TGoi/dyBIMSC\n2qppWqT9DUTF5ou8Gyo+s7pC1RqfAoDxf9RHwwPn+UoynN3F1S9NuCFCpfQ16i2V\now3Jwi7AbwjpIdMwJUrtHTmXTA+LgAoKC2KvIrD1m5daV4JCGg8qT0Gt2BdcyLq+\nd7cKUC0f+PpNa4YkdN/Qu++VhoZY6cwcP6m+eV7zYGo2a6dvnYId19Hqqb4RFZQw\ncaDNjOkCgYEA5W/a+zQLPMdnPAdLQJ3GgEdeS1e7hijKq9lc0Zz7mb4lDd7Kmn76\n78F1pv7Gwo71rhiMhAeXvpyqu0xXewH84jPTovzfTaaBGkW6jDt/5e8HgRx8KvIa\nztHrOZZA93EqZrx91wyIg8zKJd29E0za5F3p+3MqXehUp5V6Vc8RQbUCgYEA7fqh\nLjzctKpBJzwm6j6iQVb80TWOcoNdxgVfHn2OyhHXMWXQGX52XsO55pKy4tLeqO3O\nkGHoS4ZgrcsZBhcb7Ib26R08IxVtHIG6tqEz3ABhNTVj3y9CfScAbQRl38ehCmaG\nI8yJO+qd8lK0aAZfBeZTWwJaGjeaDBnGNp0Vs2cCgYA/9upHBGBppnH6g1IQhqwT\nkVIRkTj/kxnFxUiiS7C9UQyFjGpRnjsZYocJcpg5H6AQ1FlAadl9U7Ipm4P8EDbP\nXYGQPA2JWXU+vNfgRqpGkVg3P5jCZFLi/BUnLeOY2JzonX472QuqKwrkeag/3Dpe\nVmxoJNhX6/DF899yUtNNzQKBgFNDh7V30fjcQOOLZko7E+Ysm1RPmsFyORMZuggf\nAiCtUU+VQdRJrPzHGnoUBcba5NDSM53Mw8v4/kaQcvbwivKc3jL96ZaU3pJEyaEw\nkcZ904UcYw8pp+fGB54dFc/QNwY+jNxlqfZuxkiMq1ZiNEkKJ0wGbKQTpDBrrDBb\nkcYtAoGBALQlfOROeLe6gdpK3Hdfo2Wt3wEtFADyic7afFZn/wHnVTZDgpmtJ3+l\nP6XgZ5xzfAzqKimEjZsUZToRXYnCaqYRO40mcaFCWzechU1jZKj7LPBBlLqZffPc\niayfRIvyWNrC60sNToovt9VWSNM6kAA4BM3qQwr1hisEXH3Uyo8w\n-----END RSA PRIVATE KEY-----"

verify_transaction(transaction, public_key_str, signature_hex)
