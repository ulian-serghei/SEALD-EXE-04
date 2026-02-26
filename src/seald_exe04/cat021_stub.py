"""
cat021_stub — Phase-1 stub for ASTERIX CAT021 (ADS-B).

This is an intentionally simplified stub that carries only the fields needed
for the SEALD EXE#04 correlation exercise (ICAO24 + time-of-day).  It is NOT
a real ASTERIX CAT021 implementation.  Replace this module with a proper
parser in Phase 2.

Wire format (7 bytes, big-endian):
  Offset  Size  Field
  ------  ----  -----
   0       3    icao24   — 24-bit ICAO aircraft address
   3       4    tod_ms   — time-of-day in ms since midnight UTC (uint32)

NOTE: The 7-byte frame carries no length prefix.  Higher layers are expected
      to know the fixed size (CAT021_STUB_LEN).
"""

import socket
import struct
from typing import NamedTuple

CAT021_STUB_LEN: int = 7  # bytes
_PACK_FMT = ">3sI"  # 3-byte ICAO24 + uint32 TOD_MS


class Cat021Frame(NamedTuple):
    """Parsed representation of a CAT021 stub datagram."""

    icao24: bytes  # 3 bytes
    tod_ms: int    # milliseconds since midnight UTC


# ---------------------------------------------------------------------------
# Pack / unpack
# ---------------------------------------------------------------------------

def pack(icao24: bytes, tod_ms: int) -> bytes:
    """Serialise a CAT021 stub frame to bytes.

    Args:
        icao24: 3-byte ICAO aircraft address.
        tod_ms: Time-of-day in ms since midnight UTC (0 … 86_399_999).

    Returns:
        7-byte binary datagram.

    Raises:
        ValueError: if *icao24* is not exactly 3 bytes.
    """
    if len(icao24) != 3:
        raise ValueError(f"icao24 must be 3 bytes, got {len(icao24)}")
    return struct.pack(_PACK_FMT, icao24, tod_ms & 0xFFFFFFFF)


def unpack(data: bytes) -> Cat021Frame:
    """Deserialise a 7-byte CAT021 stub datagram.

    Args:
        data: Raw bytes received from the network.

    Returns:
        :class:`Cat021Frame`.

    Raises:
        ValueError: if *data* is not exactly :data:`CAT021_STUB_LEN` bytes.
    """
    if len(data) != CAT021_STUB_LEN:
        raise ValueError(
            f"CAT021 stub frame must be {CAT021_STUB_LEN} bytes, got {len(data)}"
        )
    icao24, tod_ms = struct.unpack(_PACK_FMT, data)
    return Cat021Frame(icao24=icao24, tod_ms=tod_ms)


# ---------------------------------------------------------------------------
# UDP helpers
# ---------------------------------------------------------------------------

def make_sender_socket() -> socket.socket:
    """Return a UDP socket suitable for sending CAT021 stub datagrams."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return sock


def make_receiver_socket(host: str, port: int) -> socket.socket:
    """Return a UDP socket bound to (*host*, *port*) for receiving CAT021 stub datagrams."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    return sock


def send_frame(sock: socket.socket, frame_bytes: bytes, host: str, port: int) -> None:
    """Send a serialised CAT021 stub frame via *sock*."""
    sock.sendto(frame_bytes, (host, port))
