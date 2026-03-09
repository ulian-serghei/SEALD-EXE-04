"""
Scenario 1 — Data Segmentation Accuracy (ERP-0010.01)

Objective: Verify that the callsign (SDS) is encrypted inside the CAT240
frame, while the NSDS fields (ICAO24, ToD) remain in plaintext and are
cryptographically bound via AAD.
"""

import pytest
from cryptography.exceptions import InvalidTag

from seald_exe04 import cat021_stub, cat240_seald, crypto


ICAO24    = bytes.fromhex("3C4A6B")
TOD_MS    = 43_200_000          # 12:00:00 UTC
KID       = 0
CALLSIGN  = "BAW123"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_cat240_frame(callsign: str, icao24: bytes, tod_ms: int, kid: int):
    """Return (sym_key, nonce, frame_bytes) for one CAT240 message."""
    atc_priv, atc_pub = crypto.generate_keypair()
    eph_priv, eph_pub = crypto.generate_keypair()
    sym_key = crypto.derive_shared_key(eph_priv, atc_pub, kid=kid)

    nonce     = crypto.random_nonce()
    plaintext = cat240_seald.encode_callsign(callsign)
    aad       = cat240_seald.build_aad(cat240_seald.VERSION, icao24, tod_ms, kid)
    ct_tag    = crypto.encrypt(sym_key, nonce, plaintext, aad)
    frame     = cat240_seald.pack(icao24, tod_ms, kid, nonce, ct_tag)
    return sym_key, nonce, frame, atc_priv, eph_pub


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestSdsEncryption:
    def test_callsign_not_in_plaintext_in_cat240_frame(self):
        """The raw CAT240 bytes must NOT contain the callsign in ASCII."""
        _, _, frame, _, _ = _make_cat240_frame(CALLSIGN, ICAO24, TOD_MS, KID)
        assert CALLSIGN.encode("ascii") not in frame

    def test_callsign_recoverable_after_decryption(self):
        """Decrypt the CAT240 frame and verify the callsign is recovered."""
        sym_key, nonce, frame, _, _ = _make_cat240_frame(CALLSIGN, ICAO24, TOD_MS, KID)
        parsed = cat240_seald.unpack(frame)
        aad = cat240_seald.build_aad(parsed.version, parsed.icao24, parsed.tod_ms, parsed.kid)
        plaintext = crypto.decrypt(sym_key, parsed.nonce, parsed.ct_tag, aad)
        assert cat240_seald.decode_callsign(plaintext) == CALLSIGN


class TestNsdsPlaintext:
    def test_icao24_present_in_cat021_frame(self):
        """ICAO24 (NSDS) must be present in plaintext in the CAT021 stub frame."""
        frame = cat021_stub.pack(ICAO24, TOD_MS)
        assert ICAO24 in frame

    def test_icao24_present_in_cat240_frame(self):
        """ICAO24 (NSDS) must be present in plaintext in the CAT240 frame header."""
        _, _, frame, _, _ = _make_cat240_frame(CALLSIGN, ICAO24, TOD_MS, KID)
        assert ICAO24 in frame

    def test_tod_present_in_cat021_frame(self):
        """ToD (NSDS) must be present in the CAT021 stub frame."""
        import struct
        frame = cat021_stub.pack(ICAO24, TOD_MS)
        tod_bytes = struct.pack(">I", TOD_MS)
        assert tod_bytes in frame


class TestAadBinding:
    """Modifying any NSDS field must invalidate the Poly1305 tag (AAD binding)."""

    def _encrypt_and_tamper_aad(self, override: dict) -> bytes:
        atc_priv, atc_pub = crypto.generate_keypair()
        eph_priv, eph_pub = crypto.generate_keypair()
        sym_key   = crypto.derive_shared_key(eph_priv, atc_pub, kid=KID)
        nonce     = crypto.random_nonce()
        plaintext = cat240_seald.encode_callsign(CALLSIGN)
        good_aad  = cat240_seald.build_aad(cat240_seald.VERSION, ICAO24, TOD_MS, KID)
        ct_tag    = crypto.encrypt(sym_key, nonce, plaintext, good_aad)

        bad_aad = cat240_seald.build_aad(
            override.get("version", cat240_seald.VERSION),
            override.get("icao24",  ICAO24),
            override.get("tod_ms",  TOD_MS),
            override.get("kid",     KID),
        )
        with pytest.raises(InvalidTag):
            crypto.decrypt(sym_key, nonce, ct_tag, bad_aad)

    def test_tampered_icao24_fails(self):
        self._encrypt_and_tamper_aad({"icao24": bytes.fromhex("FFFFFF")})

    def test_tampered_tod_ms_fails(self):
        self._encrypt_and_tamper_aad({"tod_ms": TOD_MS + 1})

    def test_tampered_kid_fails(self):
        self._encrypt_and_tamper_aad({"kid": KID + 1})

    def test_tampered_version_fails(self):
        self._encrypt_and_tamper_aad({"version": 0x02})
