"""Unit tests for the replay detection cache (ReplayCache)."""

import pytest
from seald_exe04.atc_node import ReplayCache


ICAO24_A = bytes.fromhex("AABBCC")
ICAO24_B = bytes.fromhex("112233")
KID_0 = 0
KID_1 = 1
NONCE_1 = b"\x01" * 12
NONCE_2 = b"\x02" * 12


class TestReplayCacheBasics:
    def test_first_packet_not_replay(self):
        cache = ReplayCache(max_age_ms=10_000)
        assert cache.check_and_add(ICAO24_A, KID_0, NONCE_1, tod_ms=1000) is False

    def test_duplicate_packet_is_replay(self):
        cache = ReplayCache(max_age_ms=10_000)
        cache.check_and_add(ICAO24_A, KID_0, NONCE_1, tod_ms=1000)
        assert cache.check_and_add(ICAO24_A, KID_0, NONCE_1, tod_ms=1000) is True

    def test_different_nonce_not_replay(self):
        cache = ReplayCache(max_age_ms=10_000)
        cache.check_and_add(ICAO24_A, KID_0, NONCE_1, tod_ms=1000)
        assert cache.check_and_add(ICAO24_A, KID_0, NONCE_2, tod_ms=2000) is False

    def test_different_icao24_not_replay(self):
        cache = ReplayCache(max_age_ms=10_000)
        cache.check_and_add(ICAO24_A, KID_0, NONCE_1, tod_ms=1000)
        assert cache.check_and_add(ICAO24_B, KID_0, NONCE_1, tod_ms=1000) is False

    def test_different_kid_not_replay(self):
        cache = ReplayCache(max_age_ms=10_000)
        cache.check_and_add(ICAO24_A, KID_0, NONCE_1, tod_ms=1000)
        assert cache.check_and_add(ICAO24_A, KID_1, NONCE_1, tod_ms=1000) is False


class TestReplayCacheEviction:
    def test_old_entry_evicted_and_reaccepted(self):
        """An entry whose tod_ms is older than max_age_ms should be evicted."""
        max_age = 5_000  # 5 seconds
        cache = ReplayCache(max_age_ms=max_age)

        tod_old = 1_000
        tod_current = tod_old + max_age + 1  # just past the eviction threshold

        # Add with old timestamp
        cache.check_and_add(ICAO24_A, KID_0, NONCE_1, tod_ms=tod_old)

        # Trigger eviction by adding a newer entry
        cache.check_and_add(ICAO24_A, KID_0, NONCE_2, tod_ms=tod_current)

        # Old entry should have been evicted; same (icao24, kid, nonce) no longer a replay
        assert cache.check_and_add(ICAO24_A, KID_0, NONCE_1, tod_ms=tod_current) is False

    def test_recent_entry_not_evicted(self):
        """An entry within the max_age window must NOT be evicted."""
        max_age = 10_000
        cache = ReplayCache(max_age_ms=max_age)

        tod_base = 1_000
        tod_current = tod_base + max_age - 1  # still within window

        cache.check_and_add(ICAO24_A, KID_0, NONCE_1, tod_ms=tod_base)
        cache.check_and_add(ICAO24_A, KID_0, NONCE_2, tod_ms=tod_current)

        # Should still be a replay
        assert cache.check_and_add(ICAO24_A, KID_0, NONCE_1, tod_ms=tod_current) is True

    def test_multiple_aircraft_independent(self):
        cache = ReplayCache(max_age_ms=10_000)
        cache.check_and_add(ICAO24_A, KID_0, NONCE_1, tod_ms=1000)
        cache.check_and_add(ICAO24_B, KID_0, NONCE_1, tod_ms=1000)

        # Replaying same nonce for aircraft A is a replay
        assert cache.check_and_add(ICAO24_A, KID_0, NONCE_1, tod_ms=2000) is True
        # But same nonce+kid for aircraft B is also a replay (both added)
        assert cache.check_and_add(ICAO24_B, KID_0, NONCE_1, tod_ms=2000) is True
