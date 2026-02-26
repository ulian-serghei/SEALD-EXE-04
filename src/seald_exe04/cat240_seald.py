"""
cat240_seald — User-defined ASTERIX CAT240 (SEALD) binary datagram format.

Fixed-length wire layout (46 bytes, big-endian):

  Offset  Size  Field
  ------  ----  -----
   0       1    version      — protocol version byte (currently 0x01)
   1       3    icao24       — 24-bit ICAO aircraft address
   4       4    tod_ms       — time-of-day in ms since midnight UTC (uint32)
   8       2    kid          — key-ID (uint16); identifies the ECDH session key
  10      12    nonce        — ChaCha20-Poly1305 nonce (random, 96-bit)
  22      24    ct_tag       — ChaCha20-Poly1305 ciphertext + Poly1305 tag
                               (8 bytes plaintext → 8 B ciphertext + 16 B tag)

  Total  46 bytes

AAD (Additional Authenticated Data) for AEAD — 10 bytes:
  version (1) || icao24 (3) || tod_ms (4) || kid (2)

The plaintext is an 8-byte callsign, ASCII-encoded and zero-padded on the right.
"""

import struct
from typing import NamedTuple

CAT240_LEN: int = 46  # bytes — total fixed frame size
_CT_TAG_LEN: int = 24  # 8 B ciphertext + 16 B Poly1305 tag
_NONCE_LEN: int = 12
_PLAINTEXT_LEN: int = 8  # callsign, zero-padded ASCII
VERSION: int = 0x01  # default / current protocol version

# struct format for the header fields (without ct_tag):
#  B  = version  (1)
#  3s = icao24   (3)
#  I  = tod_ms   (4)
#  H  = kid      (2)
#  12s = nonce   (12)
_HEADER_FMT = ">B3sIH12s"
_HEADER_LEN: int = struct.calcsize(_HEADER_FMT)  # 22 bytes


class Cat240Frame(NamedTuple):
    """Parsed representation of a CAT240 SEALD datagram."""

    version: int    # protocol version
    icao24: bytes   # 3 bytes
    tod_ms: int     # ms since midnight UTC
    kid: int        # key-ID
    nonce: bytes    # 12 bytes
    ct_tag: bytes   # 24 bytes (ciphertext + tag)


# ---------------------------------------------------------------------------
# AAD helper
# ---------------------------------------------------------------------------

def build_aad(version: int, icao24: bytes, tod_ms: int, kid: int) -> bytes:
    """Build the 10-byte AAD from header fields."""
    return struct.pack(">B3sIH", version, icao24, tod_ms, kid)


# ---------------------------------------------------------------------------
# Pack / unpack
# ---------------------------------------------------------------------------

def pack(
    icao24: bytes,
    tod_ms: int,
    kid: int,
    nonce: bytes,
    ct_tag: bytes,
    version: int = VERSION,
) -> bytes:
    """Serialise a CAT240 SEALD frame to bytes.

    Args:
        icao24:  3-byte ICAO aircraft address.
        tod_ms:  Time-of-day in ms since midnight UTC.
        kid:     Key-ID (0 … 65535).
        nonce:   12-byte ChaCha20-Poly1305 nonce.
        ct_tag:  24-byte AEAD output (ciphertext || tag).
        version: Protocol version (default 0x01).

    Returns:
        46-byte binary datagram.

    Raises:
        ValueError: on invalid field lengths.
    """
    if len(icao24) != 3:
        raise ValueError(f"icao24 must be 3 bytes, got {len(icao24)}")
    if len(nonce) != _NONCE_LEN:
        raise ValueError(f"nonce must be {_NONCE_LEN} bytes, got {len(nonce)}")
    if len(ct_tag) != _CT_TAG_LEN:
        raise ValueError(f"ct_tag must be {_CT_TAG_LEN} bytes, got {len(ct_tag)}")

    header = struct.pack(_HEADER_FMT, version, icao24, tod_ms & 0xFFFFFFFF, kid, nonce)
    return header + ct_tag


def unpack(data: bytes) -> Cat240Frame:
    """Deserialise a 46-byte CAT240 SEALD datagram.

    Args:
        data: Raw bytes received from the network.

    Returns:
        :class:`Cat240Frame`.

    Raises:
        ValueError: if *data* is not exactly :data:`CAT240_LEN` bytes.
    """
    if len(data) != CAT240_LEN:
        raise ValueError(
            f"CAT240 frame must be {CAT240_LEN} bytes, got {len(data)}"
        )
    version, icao24, tod_ms, kid, nonce = struct.unpack(
        _HEADER_FMT, data[:_HEADER_LEN]
    )
    ct_tag = data[_HEADER_LEN:]
    return Cat240Frame(
        version=version,
        icao24=icao24,
        tod_ms=tod_ms,
        kid=kid,
        nonce=nonce,
        ct_tag=ct_tag,
    )


# ---------------------------------------------------------------------------
# Callsign encode / decode helpers
# ---------------------------------------------------------------------------

def encode_callsign(callsign: str) -> bytes:
    """Encode a callsign string to 8 zero-padded ASCII bytes."""
    encoded = callsign.upper().encode("ascii", errors="replace")[:_PLAINTEXT_LEN]
    return encoded.ljust(_PLAINTEXT_LEN, b"\x00")


def decode_callsign(raw: bytes) -> str:
    """Decode an 8-byte zero-padded ASCII callsign to a string."""
    return raw.rstrip(b"\x00").decode("ascii")
