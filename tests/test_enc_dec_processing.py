"""
Scenario 2 — Encryption/Decryption Processing (ERP-0020.01 / 0020.02 / 0020.03)

Objective: Verify encryption and decryption work correctly, meet the <500 ms
latency requirement, and achieve a failure rate < 1%.
"""

import time
import pytest
from cryptography.exceptions import InvalidTag

from seald_exe04 import cat240_seald, crypto


ICAO24   = bytes.fromhex("3C4A6B")
TOD_MS   = 43_200_000
KID      = 0
CALLSIGN = "BAW123"

LATENCY_LIMIT_S  = 0.500   # 500 ms
BATCH_SIZE       = 100
MAX_FAILURE_RATE = 0.01    # 1 %


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_keys(kid: int = KID):
    atc_priv, atc_pub = crypto.generate_keypair()
    eph_priv, eph_pub = crypto.generate_keypair()
    sym_key_enc = crypto.derive_shared_key(eph_priv, atc_pub, kid=kid)
    sym_key_dec = crypto.derive_shared_key(atc_priv, eph_pub, kid=kid)
    return sym_key_enc, sym_key_dec


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestEncDecRoundtrip:
    def test_roundtrip_recovers_plaintext(self):
        """Encrypt then decrypt must recover the original callsign."""
        sym_enc, sym_dec = _make_keys()
        plaintext = cat240_seald.encode_callsign(CALLSIGN)
        nonce     = crypto.random_nonce()
        aad       = cat240_seald.build_aad(cat240_seald.VERSION, ICAO24, TOD_MS, KID)

        ct_tag    = crypto.encrypt(sym_enc, nonce, plaintext, aad)
        recovered = crypto.decrypt(sym_dec, nonce, ct_tag, aad)
        assert recovered == plaintext
        assert cat240_seald.decode_callsign(recovered) == CALLSIGN

    def test_ciphertext_overhead_is_16_bytes(self):
        """ChaCha20-Poly1305 must add exactly 16 bytes (tag) to the plaintext."""
        sym_enc, _ = _make_keys()
        plaintext  = cat240_seald.encode_callsign(CALLSIGN)
        nonce      = crypto.random_nonce()
        aad        = cat240_seald.build_aad(cat240_seald.VERSION, ICAO24, TOD_MS, KID)
        ct_tag     = crypto.encrypt(sym_enc, nonce, plaintext, aad)
        assert len(ct_tag) == len(plaintext) + 16

    def test_wrong_key_raises_invalid_tag(self):
        """Decryption with a different key must raise InvalidTag."""
        sym_enc, _     = _make_keys()
        wrong_enc, wrong_dec = _make_keys()   # unrelated keypair
        plaintext = cat240_seald.encode_callsign(CALLSIGN)
        nonce     = crypto.random_nonce()
        aad       = cat240_seald.build_aad(cat240_seald.VERSION, ICAO24, TOD_MS, KID)
        ct_tag    = crypto.encrypt(sym_enc, nonce, plaintext, aad)
        with pytest.raises(InvalidTag):
            crypto.decrypt(wrong_dec, nonce, ct_tag, aad)


class TestLatency:
    def test_encrypt_decrypt_latency_under_500ms(self):
        """Combined encrypt + decrypt must complete in < 500 ms (ERP-0020.02)."""
        sym_enc, sym_dec = _make_keys()
        plaintext = cat240_seald.encode_callsign(CALLSIGN)
        nonce     = crypto.random_nonce()
        aad       = cat240_seald.build_aad(cat240_seald.VERSION, ICAO24, TOD_MS, KID)

        t0     = time.perf_counter()
        ct_tag = crypto.encrypt(sym_enc, nonce, plaintext, aad)
        crypto.decrypt(sym_dec, nonce, ct_tag, aad)
        elapsed = time.perf_counter() - t0

        assert elapsed < LATENCY_LIMIT_S, (
            f"Encrypt+decrypt took {elapsed*1000:.1f} ms — exceeds 500 ms limit"
        )


class TestFailureRate:
    def test_batch_failure_rate_under_1_percent(self):
        """
        Send BATCH_SIZE messages; failure rate must be < 1 % (ERP-0020.03).
        A 'failure' is any exception raised during a valid encrypt→decrypt cycle.
        """
        failures = 0
        for i in range(BATCH_SIZE):
            tod = TOD_MS + i * 1000
            sym_enc, sym_dec = _make_keys()
            plaintext = cat240_seald.encode_callsign(CALLSIGN)
            nonce     = crypto.random_nonce()
            aad       = cat240_seald.build_aad(cat240_seald.VERSION, ICAO24, tod, KID)
            try:
                ct_tag    = crypto.encrypt(sym_enc, nonce, plaintext, aad)
                recovered = crypto.decrypt(sym_dec, nonce, ct_tag, aad)
                if recovered != plaintext:
                    failures += 1
            except Exception:
                failures += 1

        rate = failures / BATCH_SIZE
        assert rate < MAX_FAILURE_RATE, (
            f"Failure rate {rate:.2%} exceeds 1 % limit ({failures}/{BATCH_SIZE} failed)"
        )
