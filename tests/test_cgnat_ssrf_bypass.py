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
            reason = _private_url("https://attacker-controlled.example/")
        self.assertIsNotNone(reason)

    def test_multicast_address_is_blocked(self):
        with mock.patch("socket.getaddrinfo", return_value=_resolve_to("224.0.0.1")):
            reason = _private_url("https://attacker-controlled.example/")
        self.assertIsNotNone(reason)

    def test_ipv4_mapped_ipv6_metadata_address_is_blocked(self):
        with mock.patch("socket.getaddrinfo", return_value=_resolve_to("::ffff:169.254.169.254", socket.AF_INET6)):
            reason = _private_url("https://attacker-controlled.example/")
        self.assertIsNotNone(reason)

    def test_legitimate_public_target_is_still_allowed(self):
        with mock.patch("socket.getaddrinfo", return_value=_resolve_to("93.184.216.34")):
            reason = _private_url("https://example.com/")
        self.assertIsNone(reason)

    def test_known_previously_blocked_ranges_still_blocked(self):
        for ip in ("169.254.169.254", "127.0.0.1", "10.0.0.1", "192.168.1.1", "0.0.0.0"):
            with mock.patch("socket.getaddrinfo", return_value=_resolve_to(ip)):
                reason = _private_url("https://attacker-controlled.example/")
            self.assertIsNotNone(reason, f"{ip} should still be blocked")


if __name__ == "__main__":
    unittest.main()
