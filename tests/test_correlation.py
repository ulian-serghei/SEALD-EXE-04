"""Unit tests for the correlation window (CorrelationBuffer) and AtcNode integration."""

import pytest
from seald_exe04 import cat240_seald, crypto
from seald_exe04.atc_node import AtcNode, CorrelationBuffer


ICAO24_A = bytes.fromhex("AABBCC")
ICAO24_B = bytes.fromhex("112233")
WINDOW_MS = 2000


# ---------------------------------------------------------------------------
# CorrelationBuffer unit tests
# ---------------------------------------------------------------------------

class TestCorrelationBuffer:
    def test_no_match_empty_buffer(self):
        buf = CorrelationBuffer(window_ms=WINDOW_MS)
        assert buf.find_match(ICAO24_A, tod_ms_240=5000) is None

    def test_exact_match(self):
        buf = CorrelationBuffer(window_ms=WINDOW_MS)
        buf.add_cat021(ICAO24_A, tod_ms=5000)
        match = buf.find_match(ICAO24_A, tod_ms_240=5000)
        assert match is not None
        assert match.tod_ms == 5000

    def test_match_within_window(self):
        buf = CorrelationBuffer(window_ms=WINDOW_MS)
        buf.add_cat021(ICAO24_A, tod_ms=5000)
        # +2000 ms is exactly on the edge → should match
        assert buf.find_match(ICAO24_A, tod_ms_240=7000) is not None

    def test_no_match_outside_window(self):
        buf = CorrelationBuffer(window_ms=WINDOW_MS)
        buf.add_cat021(ICAO24_A, tod_ms=5000)
        # +2001 ms is outside window
        assert buf.find_match(ICAO24_A, tod_ms_240=7001) is None

    def test_no_match_wrong_icao24(self):
        buf = CorrelationBuffer(window_ms=WINDOW_MS)
        buf.add_cat021(ICAO24_A, tod_ms=5000)
        assert buf.find_match(ICAO24_B, tod_ms_240=5000) is None

    def test_best_match_selected(self):
        """When multiple CAT021 entries are within window, closest tod_ms wins."""
        buf = CorrelationBuffer(window_ms=WINDOW_MS)
        buf.add_cat021(ICAO24_A, tod_ms=4000)   # delta = 1500
        buf.add_cat021(ICAO24_A, tod_ms=5400)   # delta = 100 (closer)
        match = buf.find_match(ICAO24_A, tod_ms_240=5500)
        assert match is not None
        assert match.tod_ms == 5400

    def test_negative_delta_within_window(self):
        """CAT240 arrives before CAT021 (negative Δt) still correlates."""
        buf = CorrelationBuffer(window_ms=WINDOW_MS)
        buf.add_cat021(ICAO24_A, tod_ms=5000)
        # 240 arrived 1000 ms before 021
        assert buf.find_match(ICAO24_A, tod_ms_240=4000) is not None

    def test_max_per_aircraft_prunes_oldest(self):
        # Use a tight window (200 ms) so remaining entries [2000, 3000, 4000]
        # are all > 200 ms away from the dropped entry's timestamp (1000 ms).
        buf = CorrelationBuffer(window_ms=200, max_per_aircraft=3)
        for t in [1000, 2000, 3000, 4000]:
            buf.add_cat021(ICAO24_A, tod_ms=t)
        # Buffer should only keep 3 most recent: [2000, 3000, 4000]
        # tod_ms=1000 should be gone; no remaining entry is within 200 ms of 1000
        assert buf.find_match(ICAO24_A, tod_ms_240=1000) is None


# ---------------------------------------------------------------------------
# AtcNode integration tests
# ---------------------------------------------------------------------------

def _setup_atc_and_key(kid: int = 0) -> tuple:
    """Return (atc_node, sym_key) with a registered aircraft ephemeral keypair."""
    atc_priv, atc_pub = crypto.generate_keypair()
    eph_priv, eph_pub = crypto.generate_keypair()
    atc = AtcNode(atc_private_key=atc_priv, corr_window_ms=WINDOW_MS)
    atc.key_store.register(kid, eph_pub)
    sym_key = crypto.derive_shared_key(eph_priv, atc_pub, kid=kid)
    return atc, sym_key


def _make_cat240(icao24: bytes, tod_ms: int, callsign: str, sym_key: bytes, kid: int = 0) -> bytes:
    nonce = crypto.random_nonce()
    plaintext = cat240_seald.encode_callsign(callsign)
    aad = cat240_seald.build_aad(cat240_seald.VERSION, icao24, tod_ms, kid)
    ct_tag = crypto.encrypt(sym_key, nonce, plaintext, aad)
    return cat240_seald.pack(icao24, tod_ms, kid, nonce, ct_tag)


class TestAtcNodeCorrelation:
    def test_correlated_event(self):
        atc, sym_key = _setup_atc_and_key()
        tod = 50_000

        # Inject CAT021
        atc.handle_cat021(cat021_stub_bytes(ICAO24_A, tod))

        # Inject matching CAT240
        frame_240 = _make_cat240(ICAO24_A, tod, "BAW123", sym_key)
        atc.handle_cat240(frame_240)

        assert atc.metrics.correlated == 1
        assert atc.metrics.no_match == 0

    def test_no_match_no_cat021(self):
        atc, sym_key = _setup_atc_and_key()
        frame_240 = _make_cat240(ICAO24_A, 50_000, "BAW123", sym_key)
        atc.handle_cat240(frame_240)

        assert atc.metrics.no_match == 1
        assert atc.metrics.correlated == 0

    def test_replay_dropped(self):
        atc, sym_key = _setup_atc_and_key()
        atc.handle_cat021(cat021_stub_bytes(ICAO24_A, 50_000))

        # Build a CAT240 with a fixed nonce to replay it
        nonce = b"\xDE\xAD" * 6  # 12 bytes
        plaintext = cat240_seald.encode_callsign("BAW123")
        kid = 0
        tod = 50_000
        aad = cat240_seald.build_aad(cat240_seald.VERSION, ICAO24_A, tod, kid)
        ct_tag = crypto.encrypt(sym_key, nonce, plaintext, aad)
        frame_240 = cat240_seald.pack(ICAO24_A, tod, kid, nonce, ct_tag)

        atc.handle_cat240(frame_240)  # first time — OK
        atc.handle_cat240(frame_240)  # replay — should be dropped

        assert atc.metrics.replay_dropped == 1
        assert atc.metrics.correlated == 1  # first one correlated

    def test_auth_failure_on_tampered_frame(self):
        atc, sym_key = _setup_atc_and_key()
        atc.handle_cat021(cat021_stub_bytes(ICAO24_A, 50_000))

        frame_240 = bytearray(_make_cat240(ICAO24_A, 50_000, "BAW123", sym_key))
        # Tamper with the ciphertext portion (last 24 bytes)
        frame_240[-1] ^= 0xFF
        atc.handle_cat240(bytes(frame_240))

        assert atc.metrics.auth_failed == 1
        assert atc.metrics.correlated == 0

    def test_outside_correlation_window(self):
        atc, sym_key = _setup_atc_and_key()
        tod_021 = 50_000
        tod_240 = tod_021 + WINDOW_MS + 1  # 1 ms outside window

        atc.handle_cat021(cat021_stub_bytes(ICAO24_A, tod_021))
        frame_240 = _make_cat240(ICAO24_A, tod_240, "BAW123", sym_key)
        atc.handle_cat240(frame_240)

        assert atc.metrics.no_match == 1
        assert atc.metrics.correlated == 0

    def test_malformed_cat021_ignored(self):
        atc, _ = _setup_atc_and_key()
        atc.handle_cat021(b"\x00\x01\x02")  # too short
        assert atc.metrics.cat021_rx == 0

    def test_malformed_cat240_ignored(self):
        atc, _ = _setup_atc_and_key()
        atc.handle_cat240(b"\x00" * 10)  # wrong length
        assert atc.metrics.cat240_rx == 0


# ---------------------------------------------------------------------------
# Helper: build raw CAT021 stub bytes (avoid importing aircraft_sim)
# ---------------------------------------------------------------------------

from seald_exe04 import cat021_stub

def cat021_stub_bytes(icao24: bytes, tod_ms: int) -> bytes:
    return cat021_stub.pack(icao24, tod_ms)
