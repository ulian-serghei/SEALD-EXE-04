"""
Scenario 4 — Key Management: Distribution & Rotation
(ERP-0040.01 / ERP-0040.02 / ERP-0040.03)

Objective: Verify secure key generation, storage, and rotation using the
kid (Key-ID) mechanism, including backward-compatibility and deprecation.
"""

import pytest
from cryptography.exceptions import InvalidTag

from seald_exe04 import cat021_stub, cat240_seald, crypto
from seald_exe04.atc_node import AtcNode, KeyStore


ICAO24   = bytes.fromhex("3C4A6B")
TOD_BASE = 43_200_000
CALLSIGN = "MIL042"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_session(atc_priv: bytes, kid: int):
    """
    Create a new aircraft ephemeral keypair and register it at the ATC.
    Returns (node_key_store is already updated, aircraft sym_key).
    The caller must call node.key_store.register(kid, eph_pub) themselves
    so we return eph_pub for that purpose.
    """
    eph_priv, eph_pub = crypto.generate_keypair()
    sym_key = crypto.derive_shared_key(eph_priv, atc_priv, kid=kid)
    return eph_pub, sym_key


def _send_and_receive(node: AtcNode, sym_key: bytes, kid: int, tod_ms: int) -> bool:
    """Inject a CAT021 + CAT240 pair; return True if correlated count increased."""
    before = node.metrics.correlated
    node.handle_cat021(cat021_stub.pack(ICAO24, tod_ms))
    nonce     = crypto.random_nonce()
    plaintext = cat240_seald.encode_callsign(CALLSIGN)
    aad       = cat240_seald.build_aad(cat240_seald.VERSION, ICAO24, tod_ms, kid)
    ct_tag    = crypto.encrypt(sym_key, nonce, plaintext, aad)
    frame     = cat240_seald.pack(ICAO24, tod_ms, kid, nonce, ct_tag)
    node.handle_cat240(frame)
    return node.metrics.correlated > before


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestKeyGeneration:
    def test_generate_keypair_returns_32_byte_keys(self):
        priv, pub = crypto.generate_keypair()
        assert len(priv) == 32
        assert len(pub) == 32

    def test_consecutive_keypairs_are_unique(self):
        """Two consecutive keypair generations must produce different keys (ERP-0040.01)."""
        priv1, pub1 = crypto.generate_keypair()
        priv2, pub2 = crypto.generate_keypair()
        assert priv1 != priv2
        assert pub1  != pub2

    def test_different_kid_yields_different_symmetric_key(self):
        """HKDF info binding ensures kid=0 and kid=1 produce different keys (ERP-0040.02)."""
        atc_priv, atc_pub = crypto.generate_keypair()
        eph_priv, eph_pub = crypto.generate_keypair()
        key0 = crypto.derive_shared_key(eph_priv, atc_pub, kid=0)
        key1 = crypto.derive_shared_key(eph_priv, atc_pub, kid=1)
        assert key0 != key1


class TestKeyRotation:
    def test_initial_kid0_decrypts_successfully(self):
        """Messages encrypted with kid=0 must decrypt (initial key registered)."""
        atc_priv, atc_pub = crypto.generate_keypair()
        node = AtcNode(atc_private_key=atc_priv)
        eph_pub, sym_key = _make_session(atc_pub, kid=0)
        node.key_store.register(0, eph_pub)

        assert _send_and_receive(node, sym_key, kid=0, tod_ms=TOD_BASE)

    def test_rotation_to_kid1_succeeds(self):
        """After rotation, messages encrypted with kid=1 must decrypt (ERP-0040.01)."""
        atc_priv, atc_pub = crypto.generate_keypair()
        node = AtcNode(atc_private_key=atc_priv)

        # kid=0 (initial)
        eph_pub0, sym_key0 = _make_session(atc_pub, kid=0)
        node.key_store.register(0, eph_pub0)

        # kid=1 (rotation — new ephemeral keypair)
        eph_pub1, sym_key1 = _make_session(atc_pub, kid=1)
        node.key_store.register(1, eph_pub1)

        assert _send_and_receive(node, sym_key1, kid=1, tod_ms=TOD_BASE + 10_000)

    def test_backward_compatibility_old_kid_still_works(self):
        """While both keys are registered, old kid=0 messages still decrypt (ERP-0040.03)."""
        atc_priv, atc_pub = crypto.generate_keypair()
        node = AtcNode(atc_private_key=atc_priv)

        eph_pub0, sym_key0 = _make_session(atc_pub, kid=0)
        node.key_store.register(0, eph_pub0)
        eph_pub1, sym_key1 = _make_session(atc_pub, kid=1)
        node.key_store.register(1, eph_pub1)

        # kid=0 must still work while kid=1 is also registered
        assert _send_and_receive(node, sym_key0, kid=0, tod_ms=TOD_BASE + 1_000)

    def test_deregistered_kid_frames_are_dropped(self):
        """After deregister(kid=0), frames with kid=0 must be silently dropped (deprecated key)."""
        atc_priv, atc_pub = crypto.generate_keypair()
        node = AtcNode(atc_private_key=atc_priv)

        eph_pub0, sym_key0 = _make_session(atc_pub, kid=0)
        node.key_store.register(0, eph_pub0)

        # Confirm kid=0 works before deprecation
        assert _send_and_receive(node, sym_key0, kid=0, tod_ms=TOD_BASE)

        # Deprecate kid=0
        node.key_store.deregister(0)
        correlated_before = node.metrics.correlated

        # Same sym_key / kid=0 — must now be silently dropped (UNKNOWN_KID path)
        _send_and_receive(node, sym_key0, kid=0, tod_ms=TOD_BASE + 2_000)
        assert node.metrics.correlated == correlated_before   # no new correlation


class TestKeyStoreIntegrity:
    def test_keystore_stores_and_retrieves_key(self):
        """KeyStore must store and retrieve the derived symmetric key (ERP-0040.02)."""
        atc_priv, atc_pub = crypto.generate_keypair()
        eph_priv, eph_pub = crypto.generate_keypair()
        store = KeyStore(atc_private_key=atc_priv)
        store.register(0, eph_pub)
        retrieved = store.get(0)
        assert retrieved is not None
        assert len(retrieved) == 32

    def test_keystore_deregister_removes_key(self):
        """deregister() must remove the key so get() returns None."""
        atc_priv, _ = crypto.generate_keypair()
        _, eph_pub   = crypto.generate_keypair()
        store = KeyStore(atc_private_key=atc_priv)
        store.register(0, eph_pub)
        store.deregister(0)
        assert store.get(0) is None

    def test_keystore_deregister_nonexistent_is_noop(self):
        """deregister() on an unknown kid must not raise."""
        atc_priv, _ = crypto.generate_keypair()
        store = KeyStore(atc_private_key=atc_priv)
        store.deregister(99)   # must not raise
