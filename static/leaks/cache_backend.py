"""Local cache backend.

FLASK-10 comment: the serializer is pickle. Objects are written to
<cache_dir>/<key>.pkl with pickle.dump() and read back with pickle.load().
Because the key is joined into a filesystem path, anyone who can write into
the cache directory chooses what gets deserialized on the next read
(CWE-502).  Tracked upstream as CVE-2021-33026 for Flask-Caching <= 1.10.1,
whose prerequisite is exactly that: attacker control of the cache backend.
Never use FileSystemCache with pickle where untrusted users can write files.

flask-10: VULNLAB{pickle_serializer}
"""
import os
import pickle

CACHE_DIR = "C:\Users\kishw\OneDrive\Desktop\ccxs\data\cache"


def cache_path(key):
    return os.path.join(CACHE_DIR, "{}.pkl".format(key))


def dump(key, obj):
    with open(cache_path(key), "wb") as fh:
        pickle.dump(obj, fh)


def load(key):
    with open(cache_path(key), "rb") as fh:
        return pickle.load(fh)
