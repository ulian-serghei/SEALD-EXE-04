# SEALD EXE#04

TRL2 validation lab for SEALD EXE#04.

## Design choices (current)

- NSDS: ASTERIX CAT021 (ADS-B) — **Phase 1 stub** (ICAO24 + time-of-day only)
- SDS sidecar: user-defined ASTERIX CAT240 (SEALD) — fixed-length binary layout
- Transport: UDP (ports 30021 / 30240, localhost)
- Time: milliseconds since midnight UTC
- Correlation: ICAO24 + |Δt| ≤ 2000 ms
- Rate: 1 Hz per aircraft
- Crypto: X25519 (ECDH) + HKDF-SHA256 + ChaCha20-Poly1305
  - Plaintext: 8-byte ASCII callsign (zero-padded)
  - AAD binding: `version | icao24 | tod_ms | kid`
  - Replay protection cache at ATC keyed by `(icao24, kid, nonce)`

## Repository layout

```
src/
  seald_exe04/
    __init__.py       package version
    cat021_stub.py    CAT021 Phase-1 stub (pack/unpack + UDP helpers)
    cat240_seald.py   CAT240 SEALD fixed layout (pack/unpack)
    crypto.py         X25519 ECDH + HKDF-SHA256 + ChaCha20-Poly1305
    channel.py        Minimal channel impairment stub (drop/delay/tamper)
    aircraft_sim.py   1 Hz aircraft sender — CLI: seald-aircraft
    atc_node.py       ATC ground station — CLI: seald-atc
tests/
  test_cat240.py      CAT240 pack/unpack unit tests
  test_crypto.py      Crypto roundtrip unit tests
  test_replay.py      Replay detection unit tests
  test_correlation.py Correlation window unit tests
pyproject.toml
README.md
```

## Quickstart (macOS / Python 3.9.6)

### 1. Create and activate a virtual environment

```bash
python3.9 -m venv .venv
source .venv/bin/activate
```

> On macOS the system ships Python 3.9.6.  If you use another Python
> manager (pyenv, Homebrew) adjust the command accordingly.

### 2. Install the package and dependencies

```bash
pip install -e .
```

This installs the `seald-aircraft` and `seald-atc` console scripts and the
only runtime dependency: [`cryptography`](https://cryptography.io/).

To also install the test runner:

```bash
pip install pytest
```

### 3. Generate the ATC long-term keypair

```bash
seald-atc --gen-keypair --keypair atc_key.bin
```

This creates `atc_key.bin` (64 raw bytes: private || public) and prints the
public key hex on stdout.  Copy the printed hex for use in the next step.

### 4. Start the ATC node

In a **first terminal**:

```bash
seald-atc --keypair atc_key.bin --log-level DEBUG
```

The node binds to `127.0.0.1:30021` (CAT021-stub) and `127.0.0.1:30240`
(CAT240) and waits for aircraft datagrams.

### 5. Start the aircraft simulator

In a **second terminal**:

```bash
seald-aircraft \
  --callsign BAW123 \
  --icao24 3C4A6B \
  --atc-pubkey atc_key.bin \
  --log-level DEBUG
```

The aircraft generates an ephemeral X25519 keypair, derives the shared key
against the ATC public key, and emits one CAT021-stub + one CAT240 datagram
per second.

### 6. Register the aircraft ephemeral key at the ATC (out-of-band)

The aircraft prints its ephemeral public key hex at startup, e.g.:

```
Ephemeral public key (share with ATC if needed): a1b2c3...
```

Register it at the ATC (while it is running, stop with Ctrl-C first or use
`--register-kid` at startup):

```bash
seald-atc --keypair atc_key.bin \
  --register-kid 0 \
  --aircraft-eph-pub a1b2c3...
```

Once registered you should see `CORRELATED` log lines in the ATC terminal.

### 7. Run the test suite

```bash
pytest -v
```

Expected output: **56 passed**.

## CAT240 wire format (46 bytes, big-endian)

| Offset | Size | Field        | Description                                         |
|--------|------|--------------|-----------------------------------------------------|
| 0      | 1    | version      | Protocol version (0x01)                             |
| 1      | 3    | icao24       | 24-bit ICAO aircraft address                        |
| 4      | 4    | tod_ms       | Time-of-day, ms since midnight UTC (uint32)         |
| 8      | 2    | kid          | Key-ID (uint16)                                     |
| 10     | 12   | nonce        | ChaCha20-Poly1305 nonce (random, 96-bit)            |
| 22     | 24   | ct_tag       | Ciphertext (8 B) + Poly1305 tag (16 B)              |

AAD = `version (1) || icao24 (3) || tod_ms (4) || kid (2)` = 10 bytes.

## Notes

- CAT021 support in Phase 1 is intentionally a **stub** — it carries only
  the fields needed for correlation.  Replace `cat021_stub.py` with a real
  ASTERIX parser in Phase 2.
- The `channel.py` module is a pass-through stub by default.  Set
  `ChannelConfig.drop_prob`, `.tamper_prob`, or `.delay_ms` to simulate
  network impairment.
- The ATC keypair file stores raw bytes (no PEM/ASN.1 encoding) for
  simplicity.  Protect `atc_key.bin` appropriately in production.
