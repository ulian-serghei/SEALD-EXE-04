"""
atc_node — ATC ground station: UDP listeners, decrypt, correlate, log metrics.

CLI entry point: ``seald-atc``

Usage::

    # Generate (or load) long-term keypair and start listeners
    seald-atc --keypair atc_key.bin [--cat021-port 30021] [--cat240-port 30240] \\
              [--host 127.0.0.1] [--corr-window-ms 2000]

    # Generate keypair only (prints public key hex, exits)
    seald-atc --gen-keypair --keypair atc_key.bin

The keypair file stores ``private_key (32 B) || public_key (32 B)`` = 64 bytes.

Correlation logic
-----------------
When a CAT240 frame arrives the ATC node:

1. Looks up the symmetric key via kid.
2. Checks replay cache: if (icao24, kid, nonce) already seen → drop.
3. Verifies AEAD tag; on failure → log and drop.
4. Searches the recent CAT021 buffer for a matching icao24 entry with
   |tod_ms_021 - tod_ms_240| ≤ corr_window_ms.
5. On match: decrypts callsign, logs a CORRELATED event with Δt.
6. On no match: logs a NO_MATCH event (CAT021 may arrive later or was dropped).
"""

import argparse
import logging
import os
import select
import socket
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, Deque, Optional, Set, Tuple

from cryptography.exceptions import InvalidTag

from seald_exe04 import cat021_stub, cat240_seald, crypto

log = logging.getLogger(__name__)

_KEYPAIR_LEN = 64  # 32 B private + 32 B public


# ---------------------------------------------------------------------------
# Replay cache
# ---------------------------------------------------------------------------

class ReplayCache:
    """Thread-safe nonce replay detection cache.

    Keys are ``(icao24_bytes, kid, nonce_bytes)``.  Entries older than
    *max_age_ms* milliseconds (measured by tod_ms from the datagram) are
    eligible for eviction during :meth:`check_and_add`.
    """

    def __init__(self, max_age_ms: int = 10_000) -> None:
        self._max_age_ms = max_age_ms
        # Ordered deque of (tod_ms, key) for time-based eviction.
        self._ordered: Deque[Tuple[int, Tuple]] = deque()
        self._seen: Set[Tuple] = set()
        self._lock = threading.Lock()

    def check_and_add(
        self, icao24: bytes, kid: int, nonce: bytes, tod_ms: int
    ) -> bool:
        """Return *True* if the entry is a replay (already seen); add it otherwise.

        Also evicts entries whose tod_ms is more than *max_age_ms* behind
        *tod_ms* (accounting for day rollover naively).
        """
        key = (icao24, kid, nonce)
        with self._lock:
            self._evict(tod_ms)
            if key in self._seen:
                return True
            self._seen.add(key)
            self._ordered.append((tod_ms, key))
            return False

    def _evict(self, current_tod_ms: int) -> None:
        cutoff = current_tod_ms - self._max_age_ms
        while self._ordered:
            ts, k = self._ordered[0]
            if ts < cutoff:
                self._ordered.popleft()
                self._seen.discard(k)
            else:
                break


# ---------------------------------------------------------------------------
# Correlation buffer
# ---------------------------------------------------------------------------

@dataclass
class Cat021Entry:
    icao24: bytes
    tod_ms: int
    received_at: float = field(default_factory=time.monotonic)


class CorrelationBuffer:
    """Holds recent CAT021 entries for correlation with CAT240 frames.

    Keeps up to *max_per_aircraft* entries per ICAO24, pruning old ones
    beyond *max_age_ms*.
    """

    def __init__(self, window_ms: int = 2000, max_per_aircraft: int = 10) -> None:
        self._window_ms = window_ms
        self._max_per_aircraft = max_per_aircraft
        self._buf: Dict[bytes, Deque[Cat021Entry]] = {}
        self._lock = threading.Lock()

    def add_cat021(self, icao24: bytes, tod_ms: int) -> None:
        with self._lock:
            q = self._buf.setdefault(icao24, deque())
            q.append(Cat021Entry(icao24=icao24, tod_ms=tod_ms))
            # Keep only the most recent entries
            while len(q) > self._max_per_aircraft:
                q.popleft()

    def find_match(self, icao24: bytes, tod_ms_240: int) -> Optional[Cat021Entry]:
        """Return the best-matching CAT021 entry or *None*."""
        with self._lock:
            q = self._buf.get(icao24)
            if not q:
                return None
            best: Optional[Cat021Entry] = None
            best_delta = self._window_ms + 1
            for entry in q:
                delta = abs(entry.tod_ms - tod_ms_240)
                if delta <= self._window_ms and delta < best_delta:
                    best = entry
                    best_delta = delta
            return best


# ---------------------------------------------------------------------------
# Key store
# ---------------------------------------------------------------------------

class KeyStore:
    """Maps kid → symmetric key, derived from the ATC private key and the
    aircraft ephemeral public key.

    In this Phase-1 implementation the aircraft shares the derived symmetric
    key implicitly by using the ATC long-term public key.  The ATC can
    re-derive the same key given its own private key and the aircraft ephemeral
    public key.  For simplicity the store is pre-populated with keys registered
    out-of-band (e.g. the aircraft prints its ephemeral public key on startup
    and the operator registers it via :meth:`register`).
    """

    def __init__(self, atc_private_key: bytes) -> None:
        self._atc_priv = atc_private_key
        self._keys: Dict[int, bytes] = {}
        self._lock = threading.Lock()

    def register(self, kid: int, aircraft_eph_pub: bytes) -> None:
        """Derive and store the symmetric key for *kid*."""
        sym_key = crypto.derive_shared_key(self._atc_priv, aircraft_eph_pub, kid=kid)
        with self._lock:
            self._keys[kid] = sym_key
        log.info("Registered kid=%d aircraft_eph_pub=%s", kid, aircraft_eph_pub.hex())

    def get(self, kid: int) -> Optional[bytes]:
        with self._lock:
            return self._keys.get(kid)


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

@dataclass
class Metrics:
    cat021_rx: int = 0
    cat240_rx: int = 0
    correlated: int = 0
    replay_dropped: int = 0
    auth_failed: int = 0
    no_match: int = 0

    def log(self) -> None:
        log.info(
            "METRICS cat021_rx=%d cat240_rx=%d correlated=%d "
            "replay_dropped=%d auth_failed=%d no_match=%d",
            self.cat021_rx, self.cat240_rx, self.correlated,
            self.replay_dropped, self.auth_failed, self.no_match,
        )


# ---------------------------------------------------------------------------
# ATC node
# ---------------------------------------------------------------------------

class AtcNode:
    """Core ATC processing logic (transport-independent for testability)."""

    def __init__(
        self,
        atc_private_key: bytes,
        corr_window_ms: int = 2000,
    ) -> None:
        self.key_store = KeyStore(atc_private_key)
        self.replay_cache = ReplayCache(max_age_ms=max(corr_window_ms * 5, 10_000))
        self.corr_buf = CorrelationBuffer(window_ms=corr_window_ms)
        self.metrics = Metrics()

    def handle_cat021(self, data: bytes) -> None:
        try:
            frame = cat021_stub.unpack(data)
        except ValueError as exc:
            log.warning("Malformed CAT021 datagram: %s", exc)
            return
        self.metrics.cat021_rx += 1
        self.corr_buf.add_cat021(frame.icao24, frame.tod_ms)
        log.debug("CAT021 rx icao24=%s tod_ms=%d", frame.icao24.hex(), frame.tod_ms)

    def handle_cat240(self, data: bytes) -> None:
        try:
            frame = cat240_seald.unpack(data)
        except ValueError as exc:
            log.warning("Malformed CAT240 datagram: %s", exc)
            return
        self.metrics.cat240_rx += 1

        # Replay check
        if self.replay_cache.check_and_add(
            frame.icao24, frame.kid, frame.nonce, frame.tod_ms
        ):
            log.warning(
                "REPLAY_DETECTED icao24=%s kid=%d nonce=%s",
                frame.icao24.hex(), frame.kid, frame.nonce.hex(),
            )
            self.metrics.replay_dropped += 1
            return

        # Key lookup
        sym_key = self.key_store.get(frame.kid)
        if sym_key is None:
            log.warning(
                "UNKNOWN_KID kid=%d icao24=%s — register aircraft ephemeral pubkey first",
                frame.kid, frame.icao24.hex(),
            )
            return

        # Decrypt
        aad = cat240_seald.build_aad(frame.version, frame.icao24, frame.tod_ms, frame.kid)
        try:
            plaintext = crypto.decrypt(sym_key, frame.nonce, frame.ct_tag, aad)
        except InvalidTag:
            log.error(
                "AUTH_FAILED icao24=%s kid=%d tod_ms=%d",
                frame.icao24.hex(), frame.kid, frame.tod_ms,
            )
            self.metrics.auth_failed += 1
            return

        callsign = cat240_seald.decode_callsign(plaintext)

        # Correlate
        match = self.corr_buf.find_match(frame.icao24, frame.tod_ms)
        if match is not None:
            delta_t = frame.tod_ms - match.tod_ms
            log.info(
                "CORRELATED icao24=%s callsign=%s tod_ms_240=%d tod_ms_021=%d delta_t_ms=%d",
                frame.icao24.hex(), callsign, frame.tod_ms, match.tod_ms, delta_t,
            )
            self.metrics.correlated += 1
        else:
            log.warning(
                "NO_MATCH icao24=%s callsign=%s tod_ms_240=%d",
                frame.icao24.hex(), callsign, frame.tod_ms,
            )
            self.metrics.no_match += 1


# ---------------------------------------------------------------------------
# UDP listener threads
# ---------------------------------------------------------------------------

def _listener_thread(
    sock: socket.socket,
    handler,
    stop_event: threading.Event,
    label: str,
) -> None:
    while not stop_event.is_set():
        ready, _, _ = select.select([sock], [], [], 0.5)
        if ready:
            try:
                data, addr = sock.recvfrom(4096)
                log.debug("%s datagram from %s:%d (%d bytes)", label, addr[0], addr[1], len(data))
                handler(data)
            except OSError as exc:
                if not stop_event.is_set():
                    log.error("%s recv error: %s", label, exc)


# ---------------------------------------------------------------------------
# Keypair persistence
# ---------------------------------------------------------------------------

def load_or_create_keypair(path: str) -> tuple[bytes, bytes]:
    """Load ATC keypair from *path*, or generate and save if absent.

    File format: 32 B private key || 32 B public key.

    Returns:
        ``(private_key_bytes, public_key_bytes)``.
    """
    if os.path.exists(path):
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            raise ValueError(f"Cannot read keypair file {path!r}: {exc}") from exc
        if len(data) != _KEYPAIR_LEN:
            raise ValueError(
                f"Keypair file {path!r} must be {_KEYPAIR_LEN} bytes, got {len(data)}"
            )
        priv = data[:32]
        pub = data[32:]
        log.info("Loaded ATC keypair from %s  pub=%s", path, pub.hex())
        return priv, pub
    else:
        priv, pub = crypto.generate_keypair()
        try:
            with open(path, "wb") as fh:
                fh.write(priv + pub)
        except OSError as exc:
            raise ValueError(f"Cannot write keypair file {path!r}: {exc}") from exc
        log.info("Generated new ATC keypair → %s  pub=%s", path, pub.hex())
        print(f"[seald-atc] ATC public key: {pub.hex()}")
        print(f"[seald-atc] Keypair saved to: {path}")
        return priv, pub


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="seald-atc",
        description="SEALD EXE#04 — ATC node: receives CAT021-stub + CAT240, decrypts, correlates.",
    )
    p.add_argument("--keypair",       default="atc_key.bin",
                   help="Path to ATC X25519 raw keypair file (64 bytes, created if absent; default: atc_key.bin)")
    p.add_argument("--gen-keypair",   action="store_true",
                   help="Generate keypair to --keypair and exit")
    p.add_argument("--host",          default="127.0.0.1",
                   help="Bind host (default: 127.0.0.1)")
    p.add_argument("--cat021-port",   type=int, default=30021,
                   help="CAT021-stub listen port (default: 30021)")
    p.add_argument("--cat240-port",   type=int, default=30240,
                   help="CAT240 listen port (default: 30240)")
    p.add_argument("--corr-window-ms", type=int, default=2000,
                   help="Correlation time window in ms (default: 2000)")
    p.add_argument("--register-kid",  type=int, default=None,
                   help="Register a kid (requires --aircraft-eph-pub)")
    p.add_argument("--aircraft-eph-pub", default=None,
                   help="Hex-encoded 32-byte aircraft ephemeral public key for --register-kid")
    p.add_argument("--metrics-interval", type=int, default=60,
                   help="Seconds between metrics log lines (default: 60)")
    p.add_argument("--log-level",     default="INFO",
                   help="Logging level (default: INFO)")
    return p


def main() -> None:
    args = build_parser().parse_args()
    logging.basicConfig(
        level=args.log_level.upper(),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )

    priv, pub = load_or_create_keypair(args.keypair)

    if args.gen_keypair:
        return  # already saved above

    atc = AtcNode(atc_private_key=priv, corr_window_ms=args.corr_window_ms)

    # Optional: register aircraft ephemeral key out-of-band
    if args.register_kid is not None:
        if not args.aircraft_eph_pub:
            raise SystemExit("--register-kid requires --aircraft-eph-pub")
        eph_pub_bytes = bytes.fromhex(args.aircraft_eph_pub)
        atc.key_store.register(args.register_kid, eph_pub_bytes)

    # Create sockets
    sock_021 = cat021_stub.make_receiver_socket(args.host, args.cat021_port)
    sock_240 = cat021_stub.make_receiver_socket(args.host, args.cat240_port)
    log.info(
        "ATC node listening: CAT021=%s:%d  CAT240=%s:%d  corr_window=%dms",
        args.host, args.cat021_port, args.host, args.cat240_port, args.corr_window_ms,
    )

    stop_event = threading.Event()

    t1 = threading.Thread(
        target=_listener_thread,
        args=(sock_021, atc.handle_cat021, stop_event, "CAT021"),
        daemon=True,
    )
    t2 = threading.Thread(
        target=_listener_thread,
        args=(sock_240, atc.handle_cat240, stop_event, "CAT240"),
        daemon=True,
    )
    t1.start()
    t2.start()

    try:
        last_metrics = time.time()
        while True:
            time.sleep(1)
            if time.time() - last_metrics >= args.metrics_interval:
                atc.metrics.log()
                last_metrics = time.time()
    except KeyboardInterrupt:
        log.info("ATC node stopped.")
        atc.metrics.log()
    finally:
        stop_event.set()
        sock_021.close()
        sock_240.close()


if __name__ == "__main__":
    main()
