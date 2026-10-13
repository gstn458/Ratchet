from Crypto.PublicKey import ECC

key = ECC.generate(curve="P-256")
pem = key.export_key(format="PEM")
