# Practice 3 — Hash Functions and Password Storage

**Course:** 20357 Cryptography — Bachelor in Data Science and Engineering, Universidad CEU San Pablo (2026/27)  
**Author:** Miguel Roca Torres (Individual)

---

## 1. How to Run

Requires Python 3.11+ (standard library only). Run all commands from the repository root:

```bash
# Run the full test suite (9 tests covering Parts A, B, C, and D)
python -m unittest discover -s tests -v

# Part B: Avalanche effect (2,000 trials) and birthday bound (16 to 36 bits)
python measure.py

# Part C: Length-extension forgery challenge and HMAC resistance check
python forge.py

# Part D: Crack the eight unsalted SHA-256 hashes (download SecLists top 100k wordlist first)
curl -L -o wordlist.txt [https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/xato-net-10-million-passwords-100000.txt](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/xato-net-10-million-passwords-100000.txt)
python crack.py wordlist.txt
```

---

## 2. Part A3 — What a SHA-256 Digest Reveals

The two digests agree because SHA-256 processes blocks sequentially via the Merkle–Damgård construction: after absorbing `base + padding(len(base))` (64 bytes), the resulting digest is the exact 256-bit internal state fed into the next compression round, so resuming from that state with `already = 64` produces the identical computation. This reveals that a SHA-256 digest does not hide the internal chaining state—it exposes it in full, allowing anyone who knows the digest and the length of the original input to continue hashing appended data without knowing the original prefix.

---

## 3. Part B1 — Avalanche Effect

Measured over **2,000 trials** (`msglen = 32`, `seed = 20357`), flipping one random input bit per trial:

* **Measured mean:** `128.29` bits changed (out of 256)
* **Theoretical prediction:** `128.00` bits ($\text{Binomial}(256, 0.5)$)
* **Difference from theory:** `+0.29` bits (`+0.23%`)
* **Minimum / Maximum:** `102` / `162` bits

<img width="497" height="187" alt="Captura de pantalla 2026-11-26 113953" src="https://github.com/user-attachments/assets/15e77fc4-e396-4229-9d54-2f573c7f54e7" />

*\*The top bin includes the maximum observed value (`162`), as values above `159` were grouped into the last bin.*

---

## 4. Part B2 — Birthday Bound

Real collisions found by hashing `"0"`, `"1"`, `"2"`, ... in order with pure-Python SHA-256 truncated to $n$ bits:

<img width="1108" height="173" alt="Captura de pantalla 2026-11-26 115218" src="https://github.com/user-attachments/assets/44088650-65e7-4efb-a650-994b1497de4e" />

Fitting a straight line to $\log_2(\text{hashes})$ against $n$ gives:

$$\log_2(\text{hashes}) = 0.5105 \cdot n + 0.3328$$

* **Measured
 slope:** `0.5105` bits of work per extra output bit.
* **Theoretical slope:** `0.5000` bits of work per extra output bit (since expected work scales as $2^{n/2}$).
* **Is a single measurement per width enough?** No. The number of hashes until the first collision follows a Rayleigh-like distribution with high variance (coefficient of variation $\approx 52\%$), as visible in the ratios ranging from `0.79` to `1.73`. With only one sample per width, random noise easily shifts the fitted slope by several hundredths, so multiple independent trials per width are required to statistically separate `0.5105` from `0.5000`.

---

## 5. Part C — Length-Extension Forgery & HMAC

### C1 — Forging `naive_mac`

Given `message = user=student&role=guest&expires=2026-12-31` (42 bytes), `keylen = 18` bytes, and `suffix = &role=admin` (11 bytes):

* **Glue padding inserted:** `68` bytes (`18 + 42 = 60` bytes exceeds the 55-byte single-block limit, requiring a second 64-byte block; `128 - 60 = 68` bytes, ending with bit-length `480 = 0x01e0`).
* **Extended message length:** `121` bytes (`42 + 68 + 11`).
* **Extended message (hex):**
```text
757365723d73747564656e7426726f6c653d677565737426657870697265733d323032362d31322d333180000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001e026726f6c653d61646d696e
```
* **Forged tag:**
```text
b0464fec2a6ca6532b99e20da7f485d4ca0fb3ac10d39e0746d4c243b119d4d0
```
<img width="1861" height="142" alt="Captura de pantalla 2026-11-26 114646" src="https://github.com/user-attachments/assets/f1cf6813-046d-4070-8101-c6a7c2a5ca0a" />

**If the key length were unknown:** I would simply iterate over plausible key lengths $k = 1, 2, \dots, 64$ (or higher), run `forge(msg, tag, k, suffix)` for each candidate $k$, and send each `(extended_msg, forged_tag)` pair to the server until one is accepted. Since keys are typically short (16–64 bytes), this requires only a few dozen queries.

### C2 — Why HMAC Resists the Attack

HMAC computes $\text{SHA-256}((K' \oplus \text{opad}) \parallel \text{SHA-256}((K' \oplus \text{ipad}) \parallel m))$, wrapping the inner hash inside a second keyed outer hash. Even though the inner hash still uses Merkle–Damgård, the attacker never observes its output—only the output of the outer hash. Extending the outer digest would compute $\text{SHA-256}((K' \oplus \text{opad}) \parallel \text{inner} \parallel \text{pad} \parallel \text{suffix})$, which is completely unrelated to the value the server checks ($\text{SHA-256}((K' \oplus \text{opad}) \parallel \text{SHA-256}((K' \oplus \text{ipad}) \parallel m'))$), so the forgery fails.

---

## 6. Part D — Password Storage

### D1 — Cracking Unsalted Hashes

* **Dictionary used:** `xato-net-10-million-passwords-100000.txt` (SecLists) — **99,999** entries.
* **Total hashes computed:** **50** (all 8 passwords appeared within the top 50 entries, so `crack_unsalted` stopped early).
* **Elapsed time:** **0.001 s**.

<img width="701" height="230" alt="Captura de pantalla 2026-11-26 114412" src="https://github.com/user-attachments/assets/3481baa9-4ca2-4c72-863c-bd2cd02a97e4" />


### Database Rows for `123456`

<img width="803" height="88" alt="Captura de pantalla 2026-11-26 114456" src="https://github.com/user-attachments/assets/ca1d6464-efa4-405e-812c-40da96f1b19f" />

### Cost of a Per-User Salt (500 Users)

With a unique salt per user, every password candidate must be hashed separately for each user. Against a 500-user database, reaching the same depth of 50 candidates per user would require **25,000 hashes** (500× the 50 hashes computed here), and a full sweep of the 99,999-word dictionary would require **49,999,500 hashes** instead of at most 99,999.

A salt destroys precomputation (rainbow tables) and multi-user batch cracking, but it does **not** stop a fast offline dictionary or brute-force attack against a single targeted user's hash.

---

## 7. Secure Primitive vs. Secure Construction

Part A implemented SHA-256 faithfully—a cryptographically secure hash primitive with no known collisions—yet Part C completely forged tags for `naive_mac(k, m) = SHA-256(k || m)` without finding a single collision. This demonstrates that security is not automatically inherited when plugging a secure primitive into an ad-hoc scheme: SHA-256 guarantees collision and preimage resistance, not resistance to length extension, because Merkle–Damgård exposes its internal state in the digest. Building a secure MAC requires a construction like HMAC whose security proof accounts for the structural properties of the underlying primitive.

---

## Known Limitations

None — all required functions, measurements, forgery values, and unit tests pass as documented.

---

## AI Assistance Declaration

* **Tool used:** Gemini.
* **Parts assisted:** Code review and alignment of function signatures/type hints across `sha256.py`, `measure.py`, `mac.py`, `forge.py`, and `crack.py`; structuring the `tests/test_practice3.py` unit test suite; and drafting/formatting this `README.md` from my locally executed outputs.
* **Changes & verification:** I reviewed, adapted, and ran all scripts and unit tests locally, verified every output vector and measurement myself (including fixing a function-shadowing bug in `mac.py`), and ensured all reported figures come directly from my own executions.
