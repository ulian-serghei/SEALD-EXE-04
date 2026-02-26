"""
channel — Minimal stub for simulated network impairment.

This module provides simple wrappers that can inject:
  - artificial latency (delay)
  - random packet loss (drop)
  - payload corruption (tamper)

All functions accept raw datagrams (bytes) and return either the
(possibly modified) datagram or *None* to signal that the packet was
dropped.

In Phase 1 the defaults are pass-through (no impairment).  Set the
probabilities / delay via the helper :class:`ChannelConfig`.
"""

import random
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ChannelConfig:
    """Runtime-configurable channel impairment settings."""

    drop_prob: float = 0.0    # probability [0, 1] of dropping a datagram
    tamper_prob: float = 0.0  # probability [0, 1] of flipping one random byte
    delay_ms: float = 0.0     # fixed one-way latency added (milliseconds)


_DEFAULT_CFG = ChannelConfig()


def apply(
    datagram: bytes,
    cfg: ChannelConfig = _DEFAULT_CFG,
    *,
    rng: Optional[random.Random] = None,
) -> Optional[bytes]:
    """Apply channel impairment to *datagram*.

    Args:
        datagram: Raw bytes of the outgoing datagram.
        cfg:      Impairment configuration.
        rng:      Optional :class:`random.Random` instance for reproducibility
                  in tests; defaults to the module-level RNG.

    Returns:
        The (possibly modified) datagram, or *None* if the packet was dropped.
    """
    _rng = rng or random

    # Drop
    if cfg.drop_prob > 0.0 and _rng.random() < cfg.drop_prob:
        return None

    # Delay (blocking — fine for simulation)
    if cfg.delay_ms > 0.0:
        time.sleep(cfg.delay_ms / 1000.0)

    # Tamper: flip one random byte
    if cfg.tamper_prob > 0.0 and _rng.random() < cfg.tamper_prob:
        buf = bytearray(datagram)
        idx = _rng.randrange(len(buf))
        buf[idx] ^= 0xFF
        return bytes(buf)

    return datagram
