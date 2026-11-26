import hashlib
import sys
import time

TARGETS = [
    "6382deaf1f5dc6e792b76db4a4a7bf2ba468884e000b25e7928e621e27fb23cb",
    "a941a4c4fd0c01cddef61b8be963bf4c1e2b0811c037ce3f1835fddf6ef6c223",
    "203b70b5ae883932161bbd0bded9357e763e63afce98b16230be33f0b94c2cc5",
    "a9c43be948c5cabd56ef2bacffb77cdaa5eec49dd5eb0cc4129cf3eda5f0e74c",
    "e4ad93ca07acb8d908a3aa41e920ea4f4ef4f26e7f86cf8291c5db289780a5ae",
    "65e84be33532fb784c48129675f9eff3a682b27168c0ea744b2cf58ee02337c5",
    "000c285457fc971f862a79b786476c78812c8897063c6fa9c045f579a3b2d63f",
    "1c8bfe8f801d79745c4631d09fff36c82aa37fc4cce4fc946683d7b336b63032",
]

def crack_unsalted(hashes: list[str], dictionary: list[str]) -> dict[str, str]:
    targets = set(hashes)
    found: dict[str, str] = {}
    for word in dictionary:
        h = hashlib.sha256(word.encode()).hexdigest()
        if h in targets and h not in found:
            found[h] = word
            if len(found) == len(targets):
                break
    return found

if __name__ == "__main__":
    wordlist_path = sys.argv[1] if len(sys.argv) > 1 else "wordlist.txt"
    with open(wordlist_path, encoding="utf-8", errors="ignore") as f:
        dictionary = [line.strip() for line in f if line.strip()]

    t0 = time.time()
    found = crack_unsalted(TARGETS, dictionary)
    dt = time.time() - t0

    print(f"Dictionary size: {len(dictionary):,}")
    print(f"Recovered: {len(found)}/{len(TARGETS)} in {dt:.3f}s")
    for h in TARGETS:
        print(f"  {h[:16]}... -> {found.get(h, 'NOT FOUND')}")

    pwd = b"123456"
    print("\nDatabase rows for '123456':")
    print(f"  unsalted:         {hashlib.sha256(pwd).hexdigest()}")
    for s in ("a3f1c0d94e2b7865", "7b2e4f81cc09a512"):
        h = hashlib.sha256(bytes.fromhex(s) + pwd).hexdigest()
        print(f"  salt={s}: {h}")