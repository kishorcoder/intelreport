import sys
import unittest
from pathlib import Path
from unittest import mock

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services import ip_intel  # noqa: E402


def _resp(status: int, body: dict) -> httpx.Response:
    return httpx.Response(status, json=body, request=httpx.Request("GET", "http://ip-api.com/json/x"))


class FetchIpApiTest(unittest.TestCase):
    def test_success_is_returned(self):
        with mock.patch.object(ip_intel.httpx, "get", return_value=_resp(200, {"status": "success", "country": "Japan"})):
            self.assertEqual(ip_intel._fetch_ip_api("1.2.3.4")["country"], "Japan")

    def test_rate_limit_does_not_raise(self):
        with mock.patch.object(ip_intel.httpx, "get", return_value=_resp(429, {})):
            self.assertEqual(ip_intel._fetch_ip_api("1.2.3.4"), {})

    def test_timeout_does_not_raise(self):
        with mock.patch.object(ip_intel.httpx, "get", side_effect=httpx.ReadTimeout("slow")):
            self.assertEqual(ip_intel._fetch_ip_api("1.2.3.4"), {})

    def test_failed_status_is_empty(self):
        with mock.patch.object(ip_intel.httpx, "get", return_value=_resp(200, {"status": "fail", "message": "private range"})):
            self.assertEqual(ip_intel._fetch_ip_api("10.0.0.1"), {})


class ClassifyAddressTest(unittest.TestCase):
    def check(self, ip, is_private, address_type, address_range=None):
        got = ip_intel.classify_address(ip)
        self.assertEqual((got["is_private"], got["address_type"], got["address_range"]), (is_private, address_type, address_range), ip)

    def test_rfc1918_private_ranges(self):
        self.check("10.1.2.3", True, "Private network (RFC 1918)", "10.0.0.0/8")
        self.check("172.20.0.5", True, "Private network (RFC 1918)", "172.16.0.0/12")
        self.check("192.168.1.10", True, "Private network (RFC 1918)", "192.168.0.0/16")

    def test_range_edges(self):
        self.check("172.15.255.255", False, "Public")
        self.check("172.32.0.0", False, "Public")

    def test_other_special_purpose_ranges(self):
        self.check("127.0.0.1", True, "Loopback (this device)", "127.0.0.0/8")
        self.check("169.254.10.20", True, "Link-local (no DHCP address)", "169.254.0.0/16")
        self.check("100.72.1.1", True, "Carrier-grade NAT (ISP shared space)", "100.64.0.0/10")
        self.check("224.0.0.251", True, "Multicast", "224.0.0.0/4")

    def test_ipv6(self):
        self.check("::1", True, "Loopback (this device)", "::1/128")
        self.check("fd12:3456::1", True, "Private network (unique local)", "fc00::/7")
        self.check("::ffff:192.168.0.7", True, "Private network (RFC 1918)", "192.168.0.0/16")
        self.check("2606:4700:4700::1111", False, "Public")

    def test_public(self):
        self.check("8.8.8.8", False, "Public")


class PrivateLookupSkipsExternalCallsTest(unittest.TestCase):
    def test_no_ip_api_rdap_or_dns_for_private_ip(self):
        import tempfile

        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        import models
        from database import Base

        with tempfile.TemporaryDirectory() as d:
            engine = create_engine(f"sqlite:///{d}/t.db")
            Base.metadata.create_all(engine)
            db = sessionmaker(bind=engine)()
            with mock.patch.object(ip_intel, "_fetch_ip_api") as geo, \
                    mock.patch.object(ip_intel, "_fetch_rdap") as rdap, \
                    mock.patch.object(ip_intel, "_reverse_dns") as rdns:
                row = ip_intel.lookup_ip(db, "192.168.1.10")
            geo.assert_not_called(); rdap.assert_not_called(); rdns.assert_not_called()
            self.assertTrue(row.is_private)
            self.assertEqual(row.address_type, "Private network (RFC 1918)")
            self.assertEqual(row.address_range, "192.168.0.0/16")
            self.assertEqual(row.lists_checked, 14)
            db.close()


if __name__ == "__main__":
    unittest.main()
