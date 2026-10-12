from cryptography.hazmat.primitives.asymmetric import dsa

key = dsa.generate_private_key(key_size=1024)
