import hashlib


def cache_key(body):
    return hashlib.md5(body).hexdigest()


def etag(body):
    return hashlib.md5(body).hexdigest()
