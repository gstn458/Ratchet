# A project-local function that happens to be called md5. Not hashlib.
def md5(path):
    return path.upper()


md5("README")
