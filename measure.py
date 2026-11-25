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



def birthday_table(widths=(16, 20, 24, 28, 32, 36)):
    rows = []
    for n in widths:
        t0 = time.time()
        a, b, tried = find_collision(n)
        dt = time.time() - t0
        exp = math.sqrt(math.pi / 2) * 2 ** (n / 2)
        assert truncate(sha256(a.encode()), n) == truncate(sha256(b.encode()), n) and a != b
        rows.append({'bits': n, 'a': a, 'b': b, 'tried': tried,
                     'expected': round(exp), 'ratio': round(tried / exp, 2),
                     'secs': round(dt, 2)})
    return rows

def find_preimage(target: int, nbits: int, limit=1 << 26):
    for i in range(limit):
        if truncate(sha256(str(i).encode()), nbits) == target:
            return str(i), i + 1
    raise RuntimeError('sin preimagen')

def preimage_table(widths=(12, 16, 20, 24)):
    rows = []
    for n in widths:
        target = truncate(sha256(b'cryptography'), n)
        t0 = time.time()
        s, tried = find_preimage(target, n)
        dt = time.time() - t0
        assert truncate(sha256(s.encode()), n) == target
        rows.append({'bits': n, 'target': target, 'found': s, 'tried': tried,
                     'expected': 2 ** n, 'ratio': round(tried / 2 ** n, 2),
                     'secs': round(dt, 3)})
    return rows

if __name__ == '__main__':
    av = avalanche(500)
    print(f'avalancha: media {sum(av)/len(av):.1f} de 256 bits, '
          f'rango {min(av)}-{max(av)}')
    for r in birthday_table((16, 24)):
        print(f'  {r["bits"]:>2} bits: "{r["a"]}" y "{r["b"]}" en {r["tried"]:,} '
              f'intentos (esperado {r["expected"]:,}, x{r["ratio"]})')
    for r in preimage_table((12, 16)):
        print(f'  preimagen de {r["bits"]:>2} bits: "{r["found"]}" en '
              f'{r["tried"]:,} intentos (esperado {r["expected"]:,})')
