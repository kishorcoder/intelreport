import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services import blocklists as bl  # noqa: E402


class ParserTest(unittest.TestCase):
    def test_plain_drops_comments_and_trailing_notes(self):
        text = "; Spamhaus DROP\n1.10.16.0/20 ; SBL256894\n# comment\n77.91.122.9\t\t# 2026-09-29\t26\n\n"
        self.assertEqual([v for v, _ in bl.parse_plain(text)], ["1.10.16.0/20", "77.91.122.9"])

    def test_dshield_builds_cidrs(self):
        text = "#    updated: 2026-09-30\nStart\tEnd\tNetblock\n16.5.0.0\t16.5.0.255\t24\t336\t-\t-\t-\n"
        self.assertEqual([v for v, _ in bl.parse_dshield(text)], ["16.5.0.0/24"])

    def test_threatfox_keeps_malware_name(self):
        text = (
            '# "first_seen_utc","ioc_id","ioc_value","ioc_type",...\n'
            '"2026-09-30 02:05:07", "1942341", "148.66.17.125:60002", "ip:port", "botnet_cc", "win.vshell", "None", "VShell", "", "100"\n'
            '"2026-09-30 02:02:28", "1942334", "evil.example", "domain", "payload_delivery", "js.clearfake", "None", "ClearFake", "", "90"\n'
        )
        self.assertEqual(list(bl.parse_threatfox_ips(text)), [("148.66.17.125", "VShell botnet C2")])
        self.assertEqual(list(bl.parse_threatfox_domains(text)), [("evil.example", "ClearFake payload delivery")])


class RegistryTest(unittest.TestCase):
    def setUp(self):
        self.reg = bl.BlocklistRegistry()
        self.reg.lists["spamhaus_drop"].load(bl.parse_plain("203.0.113.0/24 ; SBL1\n"))
        self.reg.lists["threatfox_ip"].load([("198.51.100.7", "VShell botnet C2")])
        self.reg.lists["tor_exits"].load(bl.parse_plain("198.51.100.7\n"))
        self.reg.domain_lists["certpl"] = {"phish.example": None}
        self.reg.domain_lists["threatfox_domain"] = {"c2.example": "ClearFake payload delivery"}
        self.reg.url_lists["openphish"] = {"https://login.example/verify"}

    def test_ip_lists_every_vendor_and_names_the_malware(self):
        result = self.reg.check_ip("198.51.100.7")
        self.assertEqual(result["lists_checked"], len(bl.IP_FEEDS))
        self.assertEqual(result["hits"], ["threatfox_ip", "tor_exits"])
        self.assertTrue(result["is_tor"])
        checks = bl.build_ip_security_checks(result)
        self.assertEqual(len(checks), len(bl.IP_FEEDS))
        by_name = {c["name"]: c for c in checks}
        self.assertEqual(by_name["abuse.ch ThreatFox"]["detail"], "Listed — VShell botnet C2")
        self.assertEqual(by_name["Tor Project Exit List"]["detail"], "Listed — published Tor exit node")
        self.assertFalse(by_name["Spamhaus DROP"]["flagged"])

    def test_cidr_match(self):
        self.assertEqual(self.reg.check_ip("203.0.113.55")["hits"], ["spamhaus_drop"])
        self.assertEqual(self.reg.check_ip("192.0.2.1")["hits"], [])

    def test_domain_vendor_covers_subdomains(self):
        res = self.reg.check_url("https://a.b.phish.example/x", "a.b.phish.example")
        self.assertTrue(res["domain_match"])
        self.assertFalse(res["exact_match"])
        self.assertEqual(res["threat_type"], "phishing")
        cert = next(c for c in res["checks"] if c["name"] == "CERT Polska")
        self.assertTrue(cert["flagged"])

    def test_parent_listing_does_not_flag_other_domains(self):
        res = self.reg.check_url("https://example/", "example")
        self.assertFalse(res["domain_match"])

    def test_threatfox_domain_gives_malware_as_threat(self):
        res = self.reg.check_url("http://c2.example/gate.php", "c2.example")
        self.assertEqual(res["threat_type"], "ClearFake payload delivery")

    def test_openphish_exact_url_ignores_trailing_slash_and_case(self):
        res = self.reg.check_url("https://LOGIN.example/verify/", "login.example")
        self.assertTrue(res["exact_match"])
        self.assertEqual(res["threat_type"], "phishing")

    def test_every_url_vendor_reported_when_clean(self):
        res = self.reg.check_url("https://clean.example/", "clean.example")
        names = [c["name"] for c in res["checks"]]
        self.assertEqual(
            names,
            ["abuse.ch URLhaus (exact URL)", "abuse.ch URLhaus (domain)", "OpenPhish", "abuse.ch ThreatFox (domain)", "CERT Polska"],
        )
        self.assertFalse(any(c["flagged"] for c in res["checks"]))


class CacheTest(unittest.TestCase):
    def test_cache_from_another_url_is_stale(self):
        import tempfile
        import time

        reg = bl.BlocklistRegistry()
        with tempfile.NamedTemporaryFile("w", suffix=".meta", delete=False) as f:
            f.write(f"{time.time()} https://old.example/list.txt")
        self.assertFalse(reg._is_stale(f.name, 3600, "https://old.example/list.txt"))
        self.assertTrue(reg._is_stale(f.name, 3600, "https://new.example/list.txt"))
        # meta files written before the URL was recorded count as stale
        Path(f.name).write_text(str(time.time()))
        self.assertTrue(reg._is_stale(f.name, 3600, "https://old.example/list.txt"))
        Path(f.name).unlink()


if __name__ == "__main__":
    unittest.main()
