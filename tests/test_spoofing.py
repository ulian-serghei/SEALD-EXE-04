"""
Scenario 3 — Attack Resistance: Spoofing & Tampering (ERP-0030.02)

Objective: Verify the ATC node detects and rejects forged / tampered
encrypted messages while continuing to process legitimate traffic normally.
"""

import os
import pytest
from cryptography.exceptions import InvalidTag

from seald_exe04 import cat021_stub, cat240_seald, crypto
from seald_exe04.atc_node import AtcNode


ICAO24   = bytes.fromhex("AABBCC")
TOD_MS   = 36_000_000
KID      = 0
CALLSIGN = "MIL001"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_atc_node():
    atc_priv, atc_pub = crypto.generate_keypair()
    eph_priv, eph_pub = crypto.generate_keypair()
    node = AtcNode(atc_private_key=atc_priv)
    node.key_store.register(KID, eph_pub)
    sym_key = crypto.derive_shared_key(eph_priv, atc_pub, kid=KID)
    return node, sym_key, atc_pub


def _make_valid_cat240(sym_key: bytes, icao24: bytes, tod_ms: int, kid: int, callsign: str) -> bytes:
    nonce     = crypto.random_nonce()
    plaintext = cat240_seald.encode_callsign(callsign)
    aad       = cat240_seald.build_aad(cat240_seald.VERSION, icao24, tod_ms, kid)
    ct_tag    = crypto.encrypt(sym_key, nonce, plaintext, aad)
    return cat240_seald.pack(icao24, tod_ms, kid, nonce, ct_tag)


def _inject_cat021(node: AtcNode, icao24: bytes, tod_ms: int):
    node.handle_cat021(cat021_stub.pack(icao24, tod_ms))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestSpoofingRejection:
    def test_random_ct_tag_rejected(self):
        """A frame with a random 24-byte ct_tag must fail authentication."""
        node, _, _ = _make_atc_node()
        _inject_cat021(node, ICAO24, TOD_MS)

        # Build a frame with a completely random ct_tag
        nonce      = crypto.random_nonce()
        random_ct  = os.urandom(24)
        forged     = cat240_seald.pack(ICAO24, TOD_MS, KID, nonce, random_ct)

        node.handle_cat240(forged)

        assert node.metrics.auth_failed == 1
        assert node.metrics.correlated  == 0

    def test_tampered_ct_tag_rejected(self):
        """A frame with one flipped bit in ct_tag must fail authentication."""
        node, sym_key, _ = _make_atc_node()
        _inject_cat021(node, ICAO24, TOD_MS)

        valid = _make_valid_cat240(sym_key, ICAO24, TOD_MS, KID, CALLSIGN)
        # Flip a byte inside the ct_tag portion (offset 22 onward)
        tampered = bytearray(valid)
        tampered[22] ^= 0xFF
        node.handle_cat240(bytes(tampered))

        assert node.metrics.auth_failed == 1
        assert node.metrics.correlated  == 0

    def test_legitimate_traffic_unaffected_after_attack(self):
        """After a spoofed frame, subsequent legitimate frames must be correlated."""
        node, sym_key, _ = _make_atc_node()

        # Inject a forged frame first
        nonce     = crypto.random_nonce()
        forged    = cat240_seald.pack(ICAO24, TOD_MS, KID, nonce, os.urandom(24))
        node.handle_cat240(forged)
        assert node.metrics.auth_failed == 1

        # Now send a legitimate CAT021 + CAT240 pair
        _inject_cat021(node, ICAO24, TOD_MS + 500)
        valid = _make_valid_cat240(sym_key, ICAO24, TOD_MS + 500, KID, CALLSIGN)
        node.handle_cat240(valid)

        assert node.metrics.correlated == 1
        assert node.metrics.auth_failed == 1   # unchanged


class TestReplayRejection:
    def test_replayed_frame_rejected(self):
        """Re-sending the same CAT240 frame must be detected as a replay."""
        node, sym_key, _ = _make_atc_node()
        _inject_cat021(node, ICAO24, TOD_MS)

        valid = _make_valid_cat240(sym_key, ICAO24, TOD_MS, KID, CALLSIGN)
        node.handle_cat240(valid)
        assert node.metrics.correlated    == 1
        assert node.metrics.replay_dropped == 0

        # Replay the exact same frame
        node.handle_cat240(valid)
        assert node.metrics.replay_dropped == 1
        assert node.metrics.correlated     == 1   # not incremented again
