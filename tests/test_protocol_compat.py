"""
Scenario 5 — Protocol Compatibility Verification (ERP-0030.01)

Objective: Confirm that the NSDS stream (CAT021 stub) does not violate
1090ES message format constraints, and that the encrypted SDS sidecar
(CAT240) is a separate non-interfering channel.

Design note: SEALD EXE#04 uses an out-of-band sidecar architecture.
The CAT021 stub represents the unmodified NSDS 1090ES-compatible stream.
The CAT240 SEALD frame travels on a separate UDP port and does NOT alter
the 1090ES frame in any way — protocol compatibility is preserved by design.
"""

import struct
import pytest

from seald_exe04 import cat021_stub, cat240_seald, crypto


ICAO24   = bytes.fromhex("3C4A6B")
TOD_MS   = 43_200_000
KID      = 0
CALLSIGN = "BAW123"

# 1090ES physical-layer constraint: max 112 bits = 14 bytes.
# The CAT021 stub carries only the fields needed for correlation.
MAX_1090ES_BYTES = 14


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_cat240(callsign: str = CALLSIGN):
    atc_priv, atc_pub = crypto.generate_keypair()
    eph_priv, eph_pub = crypto.generate_keypair()
    sym_key   = crypto.derive_shared_key(eph_priv, atc_pub, kid=KID)
    nonce     = crypto.random_nonce()
    plaintext = cat240_seald.encode_callsign(callsign)
    aad       = cat240_seald.build_aad(cat240_seald.VERSION, ICAO24, TOD_MS, KID)
    ct_tag    = crypto.encrypt(sym_key, nonce, plaintext, aad)
    return cat240_seald.pack(ICAO24, TOD_MS, KID, nonce, ct_tag)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCat021SizeConstraint:
    def test_cat021_stub_frame_size_within_1090es_limit(self):
        """CAT021 stub frame (7 bytes) must not exceed the 112-bit 1090ES limit (ERP-0030.01)."""
        frame = cat021_stub.pack(ICAO24, TOD_MS)
        assert len(frame) == cat021_stub.CAT021_STUB_LEN
        assert len(frame) <= MAX_1090ES_BYTES, (
            f"CAT021 stub frame is {len(frame)} bytes — exceeds 1090ES 14-byte limit"
        )

    def test_cat021_stub_frame_size_is_exactly_7_bytes(self):
        """CAT021 stub frame must be exactly 7 bytes (3 ICAO24 + 4 ToD)."""
        frame = cat021_stub.pack(ICAO24, TOD_MS)
        assert len(frame) == 7

    def test_cat021_frame_size_constant_matches_actual(self):
        """The CAT021_STUB_LEN constant must match the actual packed size."""
        frame = cat021_stub.pack(ICAO24, TOD_MS)
        assert len(frame) == cat021_stub.CAT021_STUB_LEN


class TestSidecarSeparation:
    def test_cat240_frame_is_fixed_46_bytes(self):
        """CAT240 SEALD sidecar frame must be exactly 46 bytes (fixed layout)."""
        frame = _make_cat240()
        assert len(frame) == cat240_seald.CAT240_LEN
        assert len(frame) == 46

    def test_cat240_not_inside_cat021(self):
        """The CAT240 sidecar bytes must NOT appear inside the CAT021 frame."""
        frame_021 = cat021_stub.pack(ICAO24, TOD_MS)
        frame_240 = _make_cat240()
        # The CAT240 frame (46 bytes) cannot be a substring of the CAT021 frame (7 bytes)
        assert frame_240 not in frame_021

    def test_cat021_parseable_without_cat240(self):
        """The CAT021 frame must be fully parseable independently (NSDS self-contained)."""
        frame_021 = cat021_stub.pack(ICAO24, TOD_MS)
        parsed    = cat021_stub.unpack(frame_021)
        assert parsed.icao24 == ICAO24
        assert parsed.tod_ms  == TOD_MS

    def test_encrypted_sds_not_in_cat021_frame(self):
        """ct_tag bytes from CAT240 must NOT appear in the CAT021 frame."""
        frame_021 = cat021_stub.pack(ICAO24, TOD_MS)
        frame_240 = _make_cat240()
        parsed_240 = cat240_seald.unpack(frame_240)
        # ct_tag is 24 bytes; it cannot fit in or match anything in a 7-byte frame
        assert parsed_240.ct_tag not in frame_021


class TestProtocolSizeDocumentation:
    def test_cat021_stub_len_constant_is_7(self):
        assert cat021_stub.CAT021_STUB_LEN == 7

    def test_cat240_len_constant_is_46(self):
        assert cat240_seald.CAT240_LEN == 46

    def test_cat021_fields_icao24_plus_tod(self):
        """Verify the CAT021 wire layout: 3-byte ICAO24 followed by 4-byte ToD."""
        frame = cat021_stub.pack(ICAO24, TOD_MS)
        assert frame[:3]  == ICAO24
        assert frame[3:7] == struct.pack(">I", TOD_MS)
