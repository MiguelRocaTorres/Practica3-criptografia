import math
import random
import time
from sha256 import sha256

def avalanche(trials: int, msglen: int, seed: int) -> list[int]:
    rng = random.Random(seed)
    out = []
    for _ in range(trials):
        m = bytes(rng.getrandbits(8) for _ in range(msglen))
        i = rng.randrange(msglen * 8)
        m2 = bytearray(m)
        m2[i//8] ^= 1 << (i % 8)
        a, b = sha256(m), sha256(bytes(m2))
        out.append(sum(bin(x ^ y).count("1") for x, y in zip(a, b)))
    return out

def histogram(counts: list[int], lo: int = 96, hi: int = 160, step: int = 8) -> dict[int, int]:
    bins = {}
    for c in counts:
        k = lo + (max(lo, min(hi - 1, c)) - lo) // step * step
        bins[k] = bins.get(k, 0) + 1
    return bins

def truncate(digest: bytes, nbits: int) -> int:
    return int.from_bytes(digest, 'big') >> (len(digest) * 8 - nbits)

def find_collision(nbits: int, limit: int = 1 << 26) -> tuple[str, str, int]:
    seen = {}
    for i in range(limit):
        m = str(i).encode()
        t = truncate(sha256(m), nbits)
        if t in seen:
            return seen[t].decode(), m.decode(), i + 1
        seen[t] = m
    raise RuntimeError(f"No collision found within {limit} hashes")