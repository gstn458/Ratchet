from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

key = ECC.generate(curve="P-256")
signature = DSS.new(key, "fips-186-3").sign(SHA256.new(b"message"))
