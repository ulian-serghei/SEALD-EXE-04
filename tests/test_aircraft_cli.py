"""Unit tests for seald-aircraft CLI: --eph-keypair and --print-eph-pub."""

import os
import subprocess
import sys
import tempfile

import pytest

from seald_exe04 import crypto


class TestEphKeypair:
    def test_load_or_create_keypair_creates_file(self, tmp_path):
        """A new keypair file is created when absent."""
        kp_path = str(tmp_path / "test_key.bin")
        priv, pub = crypto.load_or_create_keypair(kp_path)
        assert os.path.exists(kp_path)
        assert len(priv) == 32
        assert len(pub) == 32

    def test_load_or_create_keypair_file_is_64_bytes(self, tmp_path):
        """Keypair file contains exactly 64 bytes (private || public)."""
        kp_path = str(tmp_path / "test_key.bin")
        crypto.load_or_create_keypair(kp_path)
        assert os.path.getsize(kp_path) == 64

    def test_load_or_create_keypair_reload_same_pubkey(self, tmp_path):
        """Loading an existing keypair yields the same public key."""
        kp_path = str(tmp_path / "test_key.bin")
        _, pub1 = crypto.load_or_create_keypair(kp_path)
        _, pub2 = crypto.load_or_create_keypair(kp_path)
        assert pub1 == pub2

    def test_load_or_create_keypair_pubkey_matches_private(self, tmp_path):
        """The public key derived from the loaded private key matches the stored public key."""
        kp_path = str(tmp_path / "test_key.bin")
        priv, pub = crypto.load_or_create_keypair(kp_path)
        assert crypto.public_key_from_private(priv) == pub

    def test_load_or_create_keypair_bad_file_raises(self, tmp_path):
        """A file with wrong size raises ValueError."""
        kp_path = str(tmp_path / "bad_key.bin")
        with open(kp_path, "wb") as fh:
            fh.write(b"\x00" * 16)
        with pytest.raises(ValueError, match="must be 64 bytes"):
            crypto.load_or_create_keypair(kp_path)


class TestPrintEphPub:
    def _run_print_eph_pub(self, extra_args=None, env=None):
        """Run seald-aircraft --print-eph-pub and return (returncode, stdout)."""
        cmd = [sys.executable, "-m", "seald_exe04.aircraft_sim", "--print-eph-pub"]
        if extra_args:
            cmd.extend(extra_args)
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env or os.environ.copy(),
        )
        return result.returncode, result.stdout.strip(), result.stderr

    def test_print_eph_pub_exits_zero(self, tmp_path):
        """--print-eph-pub exits with code 0."""
        kp_path = str(tmp_path / "aircraft_key.bin")
        rc, stdout, _ = self._run_print_eph_pub(["--eph-keypair", kp_path])
        assert rc == 0

    def test_print_eph_pub_outputs_64_hex_chars(self, tmp_path):
        """--print-eph-pub outputs exactly 64 hex characters (32 bytes)."""
        kp_path = str(tmp_path / "aircraft_key.bin")
        rc, stdout, _ = self._run_print_eph_pub(["--eph-keypair", kp_path])
        assert rc == 0
        assert len(stdout) == 64
        # Must be valid hex
        int(stdout, 16)

    def test_print_eph_pub_matches_keypair_file(self, tmp_path):
        """Printed pubkey matches the public-key portion of the keypair file."""
        kp_path = str(tmp_path / "aircraft_key.bin")
        rc, stdout, _ = self._run_print_eph_pub(["--eph-keypair", kp_path])
        assert rc == 0
        # Read the keypair file and extract pubkey (last 32 bytes)
        with open(kp_path, "rb") as fh:
            data = fh.read()
        expected_pub_hex = data[32:].hex()
        assert stdout == expected_pub_hex

    def test_print_eph_pub_consistent_across_runs(self, tmp_path):
        """Running --print-eph-pub twice with the same keypair file prints the same key."""
        kp_path = str(tmp_path / "aircraft_key.bin")
        _, pub1, _ = self._run_print_eph_pub(["--eph-keypair", kp_path])
        _, pub2, _ = self._run_print_eph_pub(["--eph-keypair", kp_path])
        assert pub1 == pub2

    def test_print_eph_pub_does_not_require_callsign_or_atc_pubkey(self, tmp_path):
        """--print-eph-pub succeeds without --callsign, --icao24, or --atc-pubkey."""
        kp_path = str(tmp_path / "aircraft_key.bin")
        rc, stdout, stderr = self._run_print_eph_pub(["--eph-keypair", kp_path])
        assert rc == 0
        assert len(stdout) == 64
