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

if __name__ == "__main__":
    av = avalanche(trials=2000, msglen=32, seed=20357)
    print(f"Avalanche ({len(av)} trials): mean={sum(av)/len(av):.2f}, min={min(av)}, max={max(av)}")

    bins: dict[int, int] = {}
    for c in av:
        k = 96 + (max(96, min(159, c)) - 96) // 8 * 8
        bins[k] = bins.get(k, 0) + 1
    for k in sorted(bins):
        print(f"  [{k:>3}, {k+7:>3}]: {bins[k]}")

    print("\nBirthday bound:")
    xs, ys = [], []
    for n in (16, 20, 24, 28, 32, 36):
        t0 = time.time()
        a, b, tried = find_collision(n)
        dt = time.time() - t0
        exp = math.sqrt(math.pi / 2) * (2 ** (n / 2))
        xs.append(float(n))
        ys.append(math.log2(tried))
        print(
            f"Bits: {n:>2} | String A: {a!r} | String B:{b!r} | "
            f" Hashes: {tried:,} | Prediction: {round(exp):,} | "
            f" Ratio: {tried / exp:.2f} | Time: {dt:.2f} |"
        )

    mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sum((x - mx) ** 2 for x in xs)
    intercept = my - slope * mx
    print(f"\nFitted line: log2(hashes) = {slope:.4f} * n + ({intercept:.4f})")