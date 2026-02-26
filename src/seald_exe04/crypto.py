"""
crypto — Cryptographic primitives for SEALD EXE#04.

Algorithm stack:
  Key exchange : X25519 ECDH
  Key derivation: HKDF-SHA256
  AEAD          : ChaCha20-Poly1305

Usage pattern (aircraft → ATC):

  # ATC side: generate long-term keypair once
  atc_priv, atc_pub = generate_keypair()

  # Aircraft side: generate ephemeral keypair per session / key-rotation
  eph_priv, eph_pub = generate_keypair()

  # Both sides compute the same shared key
  aircraft_key = derive_shared_key(eph_priv, atc_pub, kid=0)
  atc_key      = derive_shared_key(atc_priv, eph_pub, kid=0)
  assert aircraft_key == atc_key

  nonce = os.urandom(12)
  ct_tag = encrypt(aircraft_key, nonce, plaintext, aad)
  plaintext2 = decrypt(atc_key, nonce, ct_tag, aad)
"""

import os
import struct
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

_HKDF_HASH = hashes.SHA256()
_KEY_LEN = 32  # bytes for ChaCha20-Poly1305 key
_HKDF_INFO_PREFIX = b"seald-exe04-v1"


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def generate_keypair() -> tuple[bytes, bytes]:
    """Generate an X25519 keypair.

    Returns:
        ``(private_key_bytes, public_key_bytes)`` — each 32 bytes.
    """
    priv = X25519PrivateKey.generate()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv_bytes, pub_bytes


def public_key_from_private(private_key_bytes: bytes) -> bytes:
    """Derive the public key bytes from raw private key bytes."""
    priv = X25519PrivateKey.from_private_bytes(private_key_bytes)
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def derive_shared_key(
    private_key_bytes: bytes,
    peer_public_key_bytes: bytes,
    kid: int,
    salt: Optional[bytes] = None,
) -> bytes:
    """Derive a 32-byte symmetric key via X25519 ECDH + HKDF-SHA256.

    Args:
        private_key_bytes:     Raw 32-byte X25519 private key.
        peer_public_key_bytes: Raw 32-byte X25519 public key of the peer.
        kid:                   Key-ID (uint16) mixed into the HKDF info field
                               so that each rotation yields a different key.
        salt:                  Optional HKDF salt (random bytes recommended
                               in production; defaults to a zero salt per RFC
                               5869 if *None*).

    Returns:
        32-byte symmetric key.
    """
    priv = X25519PrivateKey.from_private_bytes(private_key_bytes)
    peer_pub = X25519PublicKey.from_public_bytes(peer_public_key_bytes)
    shared_secret = priv.exchange(peer_pub)

    info = _HKDF_INFO_PREFIX + b"|kid=" + struct.pack(">H", kid)
    hkdf = HKDF(algorithm=_HKDF_HASH, length=_KEY_LEN, salt=salt, info=info)
    return hkdf.derive(shared_secret)


# ---------------------------------------------------------------------------
# AEAD encrypt / decrypt
# ---------------------------------------------------------------------------

def encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """Encrypt *plaintext* with ChaCha20-Poly1305.

    Args:
        key:       32-byte symmetric key.
        nonce:     12-byte unique nonce (use :func:`os.urandom(12)` per message).
        plaintext: Bytes to encrypt.
        aad:       Additional Authenticated Data (not encrypted, but authenticated).

    Returns:
        ``ciphertext || tag`` (``len(plaintext) + 16`` bytes).
    """
    chacha = ChaCha20Poly1305(key)
    return chacha.encrypt(nonce, plaintext, aad)


def decrypt(key: bytes, nonce: bytes, ct_tag: bytes, aad: bytes) -> bytes:
    """Decrypt a ChaCha20-Poly1305 ciphertext.

    Args:
        key:    32-byte symmetric key.
        nonce:  12-byte nonce used during encryption.
        ct_tag: ``ciphertext || tag`` bytes.
        aad:    Additional Authenticated Data.

    Returns:
        Plaintext bytes.

    Raises:
        :class:`cryptography.exceptions.InvalidTag`: on authentication failure.
    """
    chacha = ChaCha20Poly1305(key)
    return chacha.decrypt(nonce, ct_tag, aad)


def random_nonce() -> bytes:
    """Return 12 cryptographically random bytes suitable as a ChaCha20 nonce."""
    return os.urandom(12)
