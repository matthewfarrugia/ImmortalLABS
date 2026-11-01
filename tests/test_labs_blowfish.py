#!/usr/bin/env python3
"""
Tests for labs_blowfish.decrypt_bytes / encrypt_bytes 

Run from the repo root:
    python3 -m unittest discover tests
"""
import hashlib
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import labs_blowfish as L
import utils

KEY = hashlib.sha512(b"immortallabs-fake-test-key").digest()

ENCRYPTED_DIR = os.path.join(HERE, "fixtures", "encrypted")
DECRYPTED_DIR = os.path.join(HERE, "fixtures", "decrypted")


def fixture_pairs():
    """Yield (relative path, encrypted bytes, decrypted bytes) for every fixture."""
    for enc_path in sorted(utils.iter_content_files(ENCRYPTED_DIR)):
        rel = os.path.relpath(enc_path, ENCRYPTED_DIR)
        with open(enc_path, "rb") as f:
            enc = f.read()
        with open(os.path.join(DECRYPTED_DIR, rel), "rb") as f:
            dec = f.read()
        yield rel, enc, dec


class TestFixtures(unittest.TestCase):
    def test_fixtures_present(self):
        pairs = list(fixture_pairs())
        self.assertEqual(len(pairs), 10)
        # Cover every content type, including a multi-chunk file (> 2048 bytes).
        exts = {os.path.splitext(rel)[1] for rel, _, _ in pairs}
        self.assertEqual(exts, {".zmulti", ".zpreset", ".zconfig"})
        self.assertTrue(any(len(dec) > L.CHUNK for _, _, dec in pairs))


class TestDecrypt(unittest.TestCase):
    def test_decrypts_to_fixture(self):
        for rel, enc, dec in fixture_pairs():
            with self.subTest(rel):
                self.assertTrue(L.is_encrypted(enc))
                self.assertEqual(L.decrypt_bytes(enc, KEY), dec)

    def test_rejects_plaintext(self):
        _, _, dec = next(fixture_pairs())
        with self.assertRaises(ValueError):
            L.decrypt_bytes(dec, KEY)

    def test_wrong_key_does_not_match(self):
        rel, enc, dec = next(fixture_pairs())
        wrong = bytes([KEY[0] ^ 0xFF]) + KEY[1:]
        self.assertNotEqual(L.decrypt_bytes(enc, wrong), dec)


class TestEncrypt(unittest.TestCase):
    def test_encrypts_to_fixture(self):
        for rel, enc, dec in fixture_pairs():
            with self.subTest(rel):
                self.assertFalse(L.is_encrypted(dec))
                self.assertEqual(L.encrypt_bytes(dec, KEY), enc)

    def test_round_trip(self):
        for rel, enc, dec in fixture_pairs():
            with self.subTest(rel):
                self.assertEqual(L.decrypt_bytes(L.encrypt_bytes(dec, KEY), KEY), dec)


if __name__ == "__main__":
    unittest.main()
