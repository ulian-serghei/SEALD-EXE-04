# SEALD EXE#04

TRL2 validation lab for SEALD EXE#04.

## Design choices (current)
- NSDS: ASTERIX CAT021 (ADS-B)
- SDS sidecar: user-defined ASTERIX CAT240 (SEALD)
- Transport: UDP
- Time: milliseconds since midnight (UTC)
- Correlation: ICAO24 + |Δt| ≤ 2000 ms
- Rate: 1 Hz per aircraft
- Crypto: X25519 (ECDH) + HKDF-SHA256 + ChaCha20-Poly1305

## Status
Repository initialized. Implementation to follow.
