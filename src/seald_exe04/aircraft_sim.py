"""
aircraft_sim — 1 Hz aircraft sender emitting CAT021-stub + CAT240 datagrams.

CLI entry point: ``seald-aircraft``

Usage::

    seald-aircraft --callsign BAW123 --icao24 3C4A6B \\
                   --atc-pubkey atc_key.bin \\
                   [--eph-keypair aircraft_key.bin] \\
                   [--cat021-port 30021] [--cat240-port 30240] \\
                   [--host 127.0.0.1] [--kid 0] [--rate-hz 1.0]

    # Print the aircraft ephemeral public key and exit (no other args needed):
    seald-aircraft --print-eph-pub [--eph-keypair aircraft_key.bin]

The ATC public key file may contain either 32 raw bytes (X25519 public key
only) or 64 raw bytes (full keypair: private || public — as written by
``seald-atc --gen-keypair``).

The aircraft ephemeral keypair is persisted in ``aircraft_key.bin`` (64 raw
bytes: private || public) so that the same public key is used across restarts.
Generate it once and register it with ``seald-atc --register-kid``.
"""

import argparse
import logging
import os
import socket
import time
from datetime import datetime, timezone

from seald_exe04 import cat021_stub, cat240_seald, crypto, channel

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tod_ms_now() -> int:
    """Return milliseconds since midnight UTC."""
    now = datetime.now(tz=timezone.utc)
    midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
    return int((now - midnight).total_seconds() * 1000) & 0xFFFFFFFF


def _send_both(
    *,
    sock_021: socket.socket,
    sock_240: socket.socket,
    host: str,
    port_021: int,
    port_240: int,
    icao24: bytes,
    tod_ms: int,
    callsign: str,
    sym_key: bytes,
    kid: int,
    ch_cfg: channel.ChannelConfig,
) -> None:
    """Build and send one CAT021-stub + CAT240 datagram pair."""
    # --- CAT021 stub ---
    frame_021 = cat021_stub.pack(icao24, tod_ms)
    impaired = channel.apply(frame_021, ch_cfg)
    if impaired is not None:
        cat021_stub.send_frame(sock_021, impaired, host, port_021)
        log.debug("sent CAT021 tod_ms=%d icao24=%s", tod_ms, icao24.hex())
    else:
        log.debug("CAT021 dropped by channel (tod_ms=%d)", tod_ms)

    # --- CAT240 SEALD ---
    nonce = crypto.random_nonce()
    plaintext = cat240_seald.encode_callsign(callsign)
    aad = cat240_seald.build_aad(cat240_seald.VERSION, icao24, tod_ms, kid)
    ct_tag = crypto.encrypt(sym_key, nonce, plaintext, aad)
    frame_240 = cat240_seald.pack(icao24, tod_ms, kid, nonce, ct_tag)
    impaired_240 = channel.apply(frame_240, ch_cfg)
    if impaired_240 is not None:
        sock_240.sendto(impaired_240, (host, port_240))
        log.debug(
            "sent CAT240 tod_ms=%d icao24=%s kid=%d nonce=%s",
            tod_ms, icao24.hex(), kid, nonce.hex(),
        )
    else:
        log.debug("CAT240 dropped by channel (tod_ms=%d)", tod_ms)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="seald-aircraft",
        description="SEALD EXE#04 — Aircraft simulator: sends CAT021-stub + CAT240 at 1 Hz.",
    )
    p.add_argument("--callsign",    required=False,         help="8-char callsign (e.g. BAW123)")
    p.add_argument("--icao24",      required=False,         help="6-hex-digit ICAO24 address (e.g. 3C4A6B)")
    p.add_argument("--atc-pubkey",  required=False,         help="Path to ATC X25519 raw public-key file (32 bytes)")
    p.add_argument("--eph-keypair", default="aircraft_key.bin",
                   help="Path to aircraft X25519 raw keypair file (64 bytes, created if absent; default: aircraft_key.bin)")
    p.add_argument("--print-eph-pub", action="store_true",
                   help="Print hex-encoded aircraft ephemeral public key and exit")
    p.add_argument("--host",        default="127.0.0.1",    help="Destination host (default: 127.0.0.1)")
    p.add_argument("--cat021-port", type=int, default=30021, help="CAT021-stub destination port (default: 30021)")
    p.add_argument("--cat240-port", type=int, default=30240, help="CAT240 destination port (default: 30240)")
    p.add_argument("--kid",         type=int, default=0,    help="Key-ID for this session (default: 0)")
    p.add_argument("--rate-hz",     type=float, default=1.0, help="Transmission rate in Hz (default: 1.0)")
    p.add_argument("--drop-prob",   type=float, default=0.0, help="Channel drop probability [0,1] (default: 0)")
    p.add_argument("--tamper-prob", type=float, default=0.0, help="Channel tamper probability [0,1] (default: 0)")
    p.add_argument("--log-level",   default="INFO",         help="Logging level (default: INFO)")
    return p


def main() -> None:
    args = build_parser().parse_args()
    logging.basicConfig(
        level=args.log_level.upper(),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )

    # Load or generate the aircraft ephemeral keypair
    eph_priv, eph_pub = crypto.load_or_create_keypair(args.eph_keypair)

    # --print-eph-pub: print hex public key and exit (no other args required)
    if args.print_eph_pub:
        print(eph_pub.hex())
        return

    # Normal run requires callsign, icao24, and atc-pubkey
    if not args.callsign:
        raise SystemExit("--callsign is required when not using --print-eph-pub")
    if not args.icao24:
        raise SystemExit("--icao24 is required when not using --print-eph-pub")
    if not args.atc_pubkey:
        raise SystemExit("--atc-pubkey is required when not using --print-eph-pub")

    # Parse ICAO24
    icao24 = bytes.fromhex(args.icao24.lstrip("0x"))
    if len(icao24) != 3:
        raise SystemExit(f"--icao24 must be a 6-hex-digit address, got: {args.icao24!r}")

    # Load ATC public key
    atc_pub_path: str = args.atc_pubkey
    try:
        with open(atc_pub_path, "rb") as fh:
            atc_pub = fh.read()
    except OSError as exc:
        raise SystemExit(f"Cannot read ATC public-key file {atc_pub_path!r}: {exc}") from exc
    if len(atc_pub) not in (32, 64):
        raise SystemExit(f"ATC public key file must be 32 or 64 bytes, got {len(atc_pub)}")
    # Support both raw-pubkey (32 B) and full keypair (64 B: private || public) files
    atc_pub = atc_pub if len(atc_pub) == 32 else atc_pub[32:]

    sym_key = crypto.derive_shared_key(eph_priv, atc_pub, kid=args.kid)
    log.info("Ephemeral public key (share with ATC if needed): %s", eph_pub.hex())
    log.info(
        "Session started: callsign=%s icao24=%s kid=%d host=%s ports=(%d,%d)",
        args.callsign, args.icao24, args.kid, args.host, args.cat021_port, args.cat240_port,
    )

    ch_cfg = channel.ChannelConfig(
        drop_prob=args.drop_prob, tamper_prob=args.tamper_prob
    )

    sock_021 = cat021_stub.make_sender_socket()
    sock_240 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    interval = 1.0 / args.rate_hz

    try:
        while True:
            t0 = time.monotonic()
            tod_ms = _tod_ms_now()
            _send_both(
                sock_021=sock_021,
                sock_240=sock_240,
                host=args.host,
                port_021=args.cat021_port,
                port_240=args.cat240_port,
                icao24=icao24,
                tod_ms=tod_ms,
                callsign=args.callsign,
                sym_key=sym_key,
                kid=args.kid,
                ch_cfg=ch_cfg,
            )
            elapsed = time.monotonic() - t0
            sleep_time = interval - elapsed
            if sleep_time > 0:
                time.sleep(sleep_time)
    except KeyboardInterrupt:
        log.info("Aircraft simulator stopped.")
    finally:
        sock_021.close()
        sock_240.close()


if __name__ == "__main__":
    main()
