import hmac
import sha256 as S
BLOCK = 64
IPAD = 0x36 
OPAD = 0x5C

def naive_mac(key: bytes, msg: bytes) -> bytes:
    return S.sha256(key + msg)

def naive_verify(key: bytes, msg: bytes, tag: bytes) -> bool:
    return hmac.compare_digest(naive_mac(key, msg), tag)

def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    if len(key) > BLOCK:
        key = S.sha256(key)
    key = key + b'\x00' * (BLOCK - len(key))
    inner = S.sha256(bytes(b ^ IPAD for b in key) + msg)
    return S.sha256(bytes(b ^ OPAD for b in key) + inner)