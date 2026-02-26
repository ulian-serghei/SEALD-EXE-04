"""Unit tests for the crypto module (keygen, derive, encrypt/decrypt roundtrip)."""

import os
import pytest
from cryptography.exceptions import InvalidTag

from seald_exe04 import crypto, cat240_seald


ICAO24 = bytes.fromhex("3C4A6B")
TOD_MS = 43_200_000  # 12:00:00 UTC
KID = 0


class TestKeypairGeneration:
    def test_generate_returns_32_bytes_each(self):
        priv, pub = crypto.generate_keypair()
        assert len(priv) == 32
        assert len(pub) == 32

    def test_generate_unique_keypairs(self):
        priv1, pub1 = crypto.generate_keypair()
        priv2, pub2 = crypto.generate_keypair()
        assert priv1 != priv2
        assert pub1 != pub2

    def test_public_key_from_private_is_consistent(self):
        priv, pub = crypto.generate_keypair()
        assert crypto.public_key_from_private(priv) == pub


class TestKeyDerivation:
    def test_shared_key_is_32_bytes(self):
        priv_a, pub_a = crypto.generate_keypair()
        priv_b, pub_b = crypto.generate_keypair()
        key = crypto.derive_shared_key(priv_a, pub_b, kid=0)
        assert len(key) == 32

    def test_ecdh_symmetric(self):
        """Both parties derive the same key."""
        priv_a, pub_a = crypto.generate_keypair()
        priv_b, pub_b = crypto.generate_keypair()
        key_ab = crypto.derive_shared_key(priv_a, pub_b, kid=0)
        key_ba = crypto.derive_shared_key(priv_b, pub_a, kid=0)
        assert key_ab == key_ba

    def test_different_kid_produces_different_key(self):
        priv_a, pub_a = crypto.generate_keypair()
        priv_b, pub_b = crypto.generate_keypair()
        key0 = crypto.derive_shared_key(priv_a, pub_b, kid=0)
        key1 = crypto.derive_shared_key(priv_a, pub_b, kid=1)
        assert key0 != key1

    def test_same_salt_deterministic(self):
        priv_a, pub_a = crypto.generate_keypair()
        priv_b, pub_b = crypto.generate_keypair()
        salt = b"\x42" * 32
        key1 = crypto.derive_shared_key(priv_a, pub_b, kid=5, salt=salt)
        key2 = crypto.derive_shared_key(priv_a, pub_b, kid=5, salt=salt)
        assert key1 == key2


class TestEncryptDecrypt:
    def _make_sym_key(self) -> bytes:
        priv_a, pub_a = crypto.generate_keypair()
        priv_b, pub_b = crypto.generate_keypair()
        return crypto.derive_shared_key(priv_a, pub_b, kid=KID)

    def test_roundtrip(self):
        key = self._make_sym_key()
        nonce = crypto.random_nonce()
        plaintext = b"BAW123\x00\x00"
        aad = cat240_seald.build_aad(0x01, ICAO24, TOD_MS, KID)
        ct_tag = crypto.encrypt(key, nonce, plaintext, aad)
        recovered = crypto.decrypt(key, nonce, ct_tag, aad)
        assert recovered == plaintext

    def test_ciphertext_length(self):
        key = self._make_sym_key()
        nonce = crypto.random_nonce()
        plaintext = b"BAW123\x00\x00"
        aad = b""
        ct_tag = crypto.encrypt(key, nonce, plaintext, aad)
        assert len(ct_tag) == len(plaintext) + 16

    def test_wrong_key_fails(self):
        key = self._make_sym_key()
        wrong_key = self._make_sym_key()
        nonce = crypto.random_nonce()
        plaintext = b"BAW123\x00\x00"
        aad = b"test_aad"
        ct_tag = crypto.encrypt(key, nonce, plaintext, aad)
        with pytest.raises(InvalidTag):
            crypto.decrypt(wrong_key, nonce, ct_tag, aad)

    def test_wrong_nonce_fails(self):
        key = self._make_sym_key()
        nonce = crypto.random_nonce()
        wrong_nonce = crypto.random_nonce()
        plaintext = b"BAW123\x00\x00"
        aad = b"test_aad"
        ct_tag = crypto.encrypt(key, nonce, plaintext, aad)
        with pytest.raises(InvalidTag):
            crypto.decrypt(key, wrong_nonce, ct_tag, aad)

    def test_wrong_aad_fails(self):
        key = self._make_sym_key()
        nonce = crypto.random_nonce()
        plaintext = b"BAW123\x00\x00"
        aad = cat240_seald.build_aad(0x01, ICAO24, TOD_MS, KID)
        wrong_aad = cat240_seald.build_aad(0x01, ICAO24, TOD_MS + 1, KID)
        ct_tag = crypto.encrypt(key, nonce, plaintext, aad)
        with pytest.raises(InvalidTag):
            crypto.decrypt(key, nonce, ct_tag, wrong_aad)

    def test_tampered_ciphertext_fails(self):
        key = self._make_sym_key()
        nonce = crypto.random_nonce()
        plaintext = b"BAW123\x00\x00"
        aad = b"aad"
        ct_tag = bytearray(crypto.encrypt(key, nonce, plaintext, aad))
        ct_tag[0] ^= 0xFF  # flip a byte
        with pytest.raises(InvalidTag):
            crypto.decrypt(key, nonce, bytes(ct_tag), aad)

    def test_random_nonce_is_12_bytes(self):
        nonce = crypto.random_nonce()
        assert len(nonce) == 12

    def test_random_nonce_is_random(self):
        n1 = crypto.random_nonce()
        n2 = crypto.random_nonce()
        assert n1 != n2  # extremely unlikely to collide
