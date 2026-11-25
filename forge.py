import sha256 as S

def forge(msg: bytes, tag: bytes, keylen: int, suffix: bytes) -> tuple[bytes, bytes]:
    absorbed = keylen + len(msg)
    glue = S.padding(absorbed)
    extended = msg + glue + suffix
    state = S.state_from_digest(tag)
    forged = S.sha256(suffix, state = state, already = absorbed + len(glue))
    return extended, forged


if __name__ == "__main__":
    from mac import hmac_sha256

    msg = b"user=student&role=guest&expires=2026-12-31"
    tag = bytes.fromhex("7daa0c342759f55c15bd8acc4a97b17f0adf1dad91e6b862cb0050afbdd92824")
    keylen = 18
    suffix = b"&role=admin"

    ext, forged = forge(msg, tag, keylen, suffix)
    glue_len = len(ext) - len(msg) - len(suffix)
    print(f"Glue padding bytes: {glue_len}")
    print(f"Extended message length: {len(ext)}")
    print(f"Extended message (hex): {ext.hex()}")
    print(f"Forged tag: {forged.hex()}")

    test_key = b"0123456789abcdef01"
    htag = hmac_sha256(test_key, msg)
    ext_h, forged_h = forge(msg, htag, len(test_key), suffix)
    print(f"Attack against HMAC accepted: {forged_h == hmac_sha256(test_key, ext_h)}")