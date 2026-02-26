"""Unit tests for cat240_seald pack/unpack and helper functions."""

import pytest
from seald_exe04 import cat240_seald


ICAO24 = bytes.fromhex("3C4A6B")
TOD_MS = 36_000_000   # 10:00:00 UTC in ms
KID = 7
NONCE = b"\x00" * 12
CT_TAG = b"\xAB" * 24  # 8 B ciphertext + 16 B tag (fake)


class TestPackUnpack:
    def test_roundtrip(self):
        raw = cat240_seald.pack(ICAO24, TOD_MS, KID, NONCE, CT_TAG)
        assert len(raw) == cat240_seald.CAT240_LEN
        frame = cat240_seald.unpack(raw)
        assert frame.icao24 == ICAO24
        assert frame.tod_ms == TOD_MS
        assert frame.kid == KID
        assert frame.nonce == NONCE
        assert frame.ct_tag == CT_TAG
        assert frame.version == 0x01

    def test_default_version(self):
        raw = cat240_seald.pack(ICAO24, TOD_MS, KID, NONCE, CT_TAG)
        frame = cat240_seald.unpack(raw)
        assert frame.version == cat240_seald.VERSION

    def test_custom_version(self):
        raw = cat240_seald.pack(ICAO24, TOD_MS, KID, NONCE, CT_TAG, version=0x02)
        frame = cat240_seald.unpack(raw)
        assert frame.version == 0x02

    def test_pack_wrong_icao24_length(self):
        with pytest.raises(ValueError, match="icao24 must be 3 bytes"):
            cat240_seald.pack(b"\x00\x01", TOD_MS, KID, NONCE, CT_TAG)

    def test_pack_wrong_nonce_length(self):
        with pytest.raises(ValueError, match="nonce must be 12 bytes"):
            cat240_seald.pack(ICAO24, TOD_MS, KID, b"\x00" * 8, CT_TAG)

    def test_pack_wrong_ct_tag_length(self):
        with pytest.raises(ValueError, match="ct_tag must be 24 bytes"):
            cat240_seald.pack(ICAO24, TOD_MS, KID, NONCE, b"\x00" * 20)

    def test_unpack_wrong_length(self):
        with pytest.raises(ValueError, match="CAT240 frame must be 46 bytes"):
            cat240_seald.unpack(b"\x00" * 10)

    def test_unpack_too_long(self):
        with pytest.raises(ValueError, match="CAT240 frame must be 46 bytes"):
            cat240_seald.unpack(b"\x00" * 50)

    def test_tod_ms_overflow_truncated(self):
        # tod_ms is stored as uint32; values exceeding 2^32 are masked
        large_tod = 0x1_FFFF_FFFF
        raw = cat240_seald.pack(ICAO24, large_tod, KID, NONCE, CT_TAG)
        frame = cat240_seald.unpack(raw)
        assert frame.tod_ms == large_tod & 0xFFFFFFFF


class TestCallsignEncoding:
    def test_encode_decode_roundtrip(self):
        for cs in ["BAW123", "KLM1234", "A", "LONGTEST"]:
            encoded = cat240_seald.encode_callsign(cs)
            assert len(encoded) == 8
            decoded = cat240_seald.decode_callsign(encoded)
            assert decoded == cs.upper()[:8]

    def test_encode_pads_to_8_bytes(self):
        encoded = cat240_seald.encode_callsign("AB")
        assert len(encoded) == 8
        assert encoded == b"AB\x00\x00\x00\x00\x00\x00"

    def test_encode_truncates_to_8_bytes(self):
        encoded = cat240_seald.encode_callsign("ABCDEFGHIJ")
        assert len(encoded) == 8
        assert encoded == b"ABCDEFGH"

    def test_encode_uppercases(self):
        encoded = cat240_seald.encode_callsign("baw123")
        assert encoded.startswith(b"BAW123")


class TestBuildAad:
    def test_aad_length(self):
        aad = cat240_seald.build_aad(0x01, ICAO24, TOD_MS, KID)
        assert len(aad) == 10  # 1+3+4+2

    def test_aad_changes_with_version(self):
        aad1 = cat240_seald.build_aad(0x01, ICAO24, TOD_MS, KID)
        aad2 = cat240_seald.build_aad(0x02, ICAO24, TOD_MS, KID)
        assert aad1 != aad2

    def test_aad_changes_with_icao24(self):
        aad1 = cat240_seald.build_aad(0x01, ICAO24, TOD_MS, KID)
        aad2 = cat240_seald.build_aad(0x01, bytes.fromhex("AABBCC"), TOD_MS, KID)
        assert aad1 != aad2

    def test_aad_changes_with_tod_ms(self):
        aad1 = cat240_seald.build_aad(0x01, ICAO24, TOD_MS, KID)
        aad2 = cat240_seald.build_aad(0x01, ICAO24, TOD_MS + 1, KID)
        assert aad1 != aad2

    def test_aad_changes_with_kid(self):
        aad1 = cat240_seald.build_aad(0x01, ICAO24, TOD_MS, 0)
        aad2 = cat240_seald.build_aad(0x01, ICAO24, TOD_MS, 1)
        assert aad1 != aad2
