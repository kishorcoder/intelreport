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


if __name__ == "__main__":
    unittest.main()
