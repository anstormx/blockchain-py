import json
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

transaction = {
    'sender': "Alice",
    'receiver': "Bob",
    'amount': 10,
    'nonce': 1 
}

private_key = RSA.import_key("""-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1UktazHclHqtQ679wcmym1ov7T6cvrRwkkfXFkrDggaW/thN\nnm7TkAI3lPh2N+trB2oFNQ8IQpvgRfxvckrPjGyPuKQk3u2b+bOa85gTgYULW7ob\nR4VBo1p2KlKyzc9lIzzDSSpb9pBwIwJeabN7IvTs1sMU/Tlm5oyFn6qHRVeGzMan\nP2jhExkrjreTiCKiIsN2hsWxZaEAbx0uHft6pQ6SjQKe4hLRBW4TRkXF0wKeSINV\nHZVK4wuLWPHZ/d+L54rpXwEzA+gouMzaQ8qOBFmw2m97NxUQOgRk5iGiMxA2Qz8h\nBxZICCVFNaT8xKuiD+eYUzERtG2H2KQzxbv+0wIDAQABAoIBAE4kaGKMux8fLxnM\nJCZ6ylhGm6aVOQJZw6Ckd3YwYB7kYS/vecihHBv34/tNaKqmMulde5jr7//PckTR\n7tb198KgB6wDX4rZjTrYBd5XilX6s6WgstvqQ5kgzIhHEkF7Sbe2TGoi/dyBIMSC\n2qppWqT9DUTF5ou8Gyo+s7pC1RqfAoDxf9RHwwPn+UoynN3F1S9NuCFCpfQ16i2V\now3Jwi7AbwjpIdMwJUrtHTmXTA+LgAoKC2KvIrD1m5daV4JCGg8qT0Gt2BdcyLq+\nd7cKUC0f+PpNa4YkdN/Qu++VhoZY6cwcP6m+eV7zYGo2a6dvnYId19Hqqb4RFZQw\ncaDNjOkCgYEA5W/a+zQLPMdnPAdLQJ3GgEdeS1e7hijKq9lc0Zz7mb4lDd7Kmn76\n78F1pv7Gwo71rhiMhAeXvpyqu0xXewH84jPTovzfTaaBGkW6jDt/5e8HgRx8KvIa\nztHrOZZA93EqZrx91wyIg8zKJd29E0za5F3p+3MqXehUp5V6Vc8RQbUCgYEA7fqh\nLjzctKpBJzwm6j6iQVb80TWOcoNdxgVfHn2OyhHXMWXQGX52XsO55pKy4tLeqO3O\nkGHoS4ZgrcsZBhcb7Ib26R08IxVtHIG6tqEz3ABhNTVj3y9CfScAbQRl38ehCmaG\nI8yJO+qd8lK0aAZfBeZTWwJaGjeaDBnGNp0Vs2cCgYA/9upHBGBppnH6g1IQhqwT\nkVIRkTj/kxnFxUiiS7C9UQyFjGpRnjsZYocJcpg5H6AQ1FlAadl9U7Ipm4P8EDbP\nXYGQPA2JWXU+vNfgRqpGkVg3P5jCZFLi/BUnLeOY2JzonX472QuqKwrkeag/3Dpe\nVmxoJNhX6/DF899yUtNNzQKBgFNDh7V30fjcQOOLZko7E+Ysm1RPmsFyORMZuggf\nAiCtUU+VQdRJrPzHGnoUBcba5NDSM53Mw8v4/kaQcvbwivKc3jL96ZaU3pJEyaEw\nkcZ904UcYw8pp+fGB54dFc/QNwY+jNxlqfZuxkiMq1ZiNEkKJ0wGbKQTpDBrrDBb\nkcYtAoGBALQlfOROeLe6gdpK3Hdfo2Wt3wEtFADyic7afFZn/wHnVTZDgpmtJ3+l\nP6XgZ5xzfAzqKimEjZsUZToRXYnCaqYRO40mcaFCWzechU1jZKj7LPBBlLqZffPc\niayfRIvyWNrC60sNToovt9VWSNM6kAA4BM3qQwr1hisEXH3Uyo8w\n-----END RSA PRIVATE KEY-----""")

transaction_data = json.dumps(transaction, sort_keys=True).encode()
hash_object = SHA256.new(transaction_data)
signature = pkcs1_15.new(private_key).sign(hash_object)

print("Signature:", signature.hex())

#-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1UktazHclHqtQ679wcmy\nm1ov7T6cvrRwkkfXFkrDggaW/thNnm7TkAI3lPh2N+trB2oFNQ8IQpvgRfxvckrP\njGyPuKQk3u2b+bOa85gTgYULW7obR4VBo1p2KlKyzc9lIzzDSSpb9pBwIwJeabN7\nIvTs1sMU/Tlm5oyFn6qHRVeGzManP2jhExkrjreTiCKiIsN2hsWxZaEAbx0uHft6\npQ6SjQKe4hLRBW4TRkXF0wKeSINVHZVK4wuLWPHZ/d+L54rpXwEzA+gouMzaQ8qO\nBFmw2m97NxUQOgRk5iGiMxA2Qz8hBxZICCVFNaT8xKuiD+eYUzERtG2H2KQzxbv+\n0wIDAQAB\n-----END PUBLIC KEY-----