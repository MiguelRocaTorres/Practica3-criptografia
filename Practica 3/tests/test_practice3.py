import hashlib
import random
import unittest

import crack
import forge
import mac
import measure
import sha256


class TestSHA256(unittest.TestCase):
    def test_padding_table(self):
        cases = [
            (0, 64, "0000000000000000"),
            (3, 61, "0000000000000018"),
            (55, 9, "00000000000001b8"),
            (56, 72, "00000000000001c0"),
            (63, 65, "00000000000001f8"),
            (64, 64, "0000000000000200"),
            (119, 9, "00000000000003b8"),
            (1000, 24, "0000000000001f40"),
        ]
        for msglen, expected_len, last8 in cases:
            pad = sha256.padding(msglen)
            self.assertEqual(len(pad), expected_len)
            self.assertEqual((msglen + len(pad)) % 64, 0)
            self.assertEqual(pad[0], 0x80)
            self.assertEqual(pad[-8:].hex(), last8)

    def test_sha256_vectors(self):
        vectors = [
            (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            (b"cryptography", "e06554818e902b4ba339f066967c0000da3fcda4fd7eb4ef89c124fa78bda419"),
            (b"Cryptography", "b584eec728548aced5a66c0267dd520a00871b5e7b735b2d8202f86719f61857"),
        ]
        for msg, expected in vectors:
            self.assertEqual(sha256.sha256(msg).hex(), expected)

    def test_sha256_random_and_boundaries(self):
        rng = random.Random(20357)
        boundary_lengths = [0, 1, 54, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129, 256]
        random_lengths = [rng.randint(0, 500) for _ in range(100)]
        for length in boundary_lengths + random_lengths:
            data = bytes(rng.getrandbits(8) for _ in range(length))
            self.assertEqual(sha256.sha256(data), hashlib.sha256(data).digest())

    def test_resumable_state(self):
        base = b"the first part"
        d1 = sha256.sha256(base)
        self.assertEqual(
            d1.hex(),
            "d2bba6892bc661a48fd99f726bdf084a4e53e9644d03f06002eb2c1d11ac194d",
        )
        resumed = sha256.sha256(
            b"and the rest",
            state=sha256.state_from_digest(d1),
            already=64,
        )
        direct = sha256.sha256(base + sha256.padding(len(base)) + b"and the rest")
        self.assertEqual(
            resumed.hex(),
            "cb32e653bcd5ed0800832787b264fab57a61f652a391177224fa3cbb1aab740d",
        )
        self.assertEqual(resumed, direct)


class TestMACAndForge(unittest.TestCase):
    def test_hmac_vectors(self):
        vectors = [
            (
                b"\x0b" * 20,
                b"Hi There",
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            ),
            (
                b"Jefe",
                b"what do ya want for nothing?",
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            ),
            (
                b"secret",
                b"user=student&role=guest",
                "b4d022e95ee9053940f3514268c414bbc5571d891a3430487fc2e59a07e8039c",
            ),
        ]
        for key, msg, expected in vectors:
            self.assertEqual(mac.hmac_sha256(key, msg).hex(), expected)

    def test_length_extension_forgery(self):
        key = b"my-custom-secret-key"
        msg = b"user=student&role=guest&expires=2026-12-31"
        suffix = b"&role=admin"
        tag = mac.naive_mac(key, msg)

        ext, forged_tag = forge.forge(msg, tag, len(key), suffix)
        self.assertTrue(ext.endswith(suffix))
        self.assertTrue(mac.naive_verify(key, ext, forged_tag))

    def test_length_extension_fails_on_hmac(self):
        key = b"my-custom-secret-key"
        msg = b"user=student&role=guest&expires=2026-12-31"
        suffix = b"&role=admin"
        htag = mac.hmac_sha256(key, msg)

        ext, forged_tag = forge.forge(msg, htag, len(key), suffix)
        self.assertNotEqual(forged_tag, mac.hmac_sha256(key, ext))


class TestMeasureAndCrack(unittest.TestCase):
    def test_find_collision(self):
        nbits = 16
        a, b, tried = measure.find_collision(nbits)
        self.assertNotEqual(a, b)
        self.assertGreater(tried, 0)
        ta = measure.truncate(sha256.sha256(a.encode()), nbits)
        tb = measure.truncate(sha256.sha256(b.encode()), nbits)
        self.assertEqual(ta, tb)

    def test_crack_unsalted(self):
        words = ["123456", "password", "qwerty"]
        targets = [hashlib.sha256(w.encode()).hexdigest() for w in words[:2]]
        found = crack.crack_unsalted(targets, words)
        self.assertEqual(found[targets[0]], "123456")
        self.assertEqual(found[targets[1]], "password")

if __name__ == "__main__":
    unittest.main()