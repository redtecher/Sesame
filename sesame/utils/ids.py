import hashlib


def stable_id(*parts: str) -> str:
    data = "::".join(parts).encode()
    return hashlib.sha1(data).hexdigest()[:12]

