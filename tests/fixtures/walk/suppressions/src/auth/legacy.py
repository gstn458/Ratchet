import hashlib


def password_hash(password):
    # The same algorithm as src/cache, but not covered by the suppression.
    return hashlib.md5(password).hexdigest()
