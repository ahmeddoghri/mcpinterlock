import socket
import unittest
from unittest import mock

from mcpinterlock.core import _private_url


def _resolve_to(ip: str, family=socket.AF_INET):
    return [(family, socket.SOCK_STREAM, 6, "", (ip, 0))]


class CGNATSSRFBypassTest(unittest.TestCase):
    """_private_url used `is_private or is_loopback or is_link_local or
    is_reserved`, but Python's ipaddress module does not classify RFC 6598
    carrier-grade-NAT shared address space (100.64.0.0/10) as private --
    that range is used internally by real cloud providers and is
    explicitly non-public per the RFC, but none of those four properties
    catch it. Multicast addresses (is_global=True in Python's ipaddress
    module) weren't covered by any of them either."""

    def test_cgnat_shared_address_space_is_blocked(self):
        with mock.patch("socket.getaddrinfo", return_value=_resolve_to("100.64.0.5")):
            reasons = _private_url("https://attacker-controlled.example/")
        self.assertTrue(reasons)

    def test_multicast_address_is_blocked(self):
        with mock.patch("socket.getaddrinfo", return_value=_resolve_to("224.0.0.1")):
            reasons = _private_url("https://attacker-controlled.example/")
        self.assertTrue(reasons)

    def test_ipv4_mapped_ipv6_metadata_address_is_blocked(self):
        with mock.patch("socket.getaddrinfo", return_value=_resolve_to("::ffff:169.254.169.254", socket.AF_INET6)):
            reasons = _private_url("https://attacker-controlled.example/")
        self.assertTrue(reasons)

    def test_legitimate_public_target_is_still_allowed(self):
        with mock.patch("socket.getaddrinfo", return_value=_resolve_to("93.184.216.34")):
            reasons = _private_url("https://example.com/")
        self.assertEqual(reasons, [])

    def test_known_previously_blocked_ranges_still_blocked(self):
        for ip in ("169.254.169.254", "127.0.0.1", "10.0.0.1", "192.168.1.1", "0.0.0.0"):
            with mock.patch("socket.getaddrinfo", return_value=_resolve_to(ip)):
                reasons = _private_url("https://attacker-controlled.example/")
            self.assertTrue(reasons, f"{ip} should still be blocked")


class AllReasonsReportedTest(unittest.TestCase):
    """Returning on the first failure hid the finding that mattered: the
    demo's cloud-metadata URL is plain HTTP, so it was denied for the scheme
    and the address check never ran."""

    def test_http_metadata_url_reports_both_the_scheme_and_the_address(self):
        with mock.patch("socket.getaddrinfo", return_value=_resolve_to("169.254.169.254")):
            reasons = _private_url("http://169.254.169.254/latest/meta-data/iam")
        self.assertEqual(len(reasons), 2, reasons)
        self.assertTrue(any("HTTPS" in reason for reason in reasons), reasons)
        self.assertTrue(any("non-public" in reason for reason in reasons), reasons)


if __name__ == "__main__":
    unittest.main()
