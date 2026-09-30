import csv
import ipaddress
import os
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable, Iterable
from urllib.parse import urlparse

import httpx

CACHE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data_cache")
os.makedirs(CACHE_DIR, exist_ok=True)

IP_REFRESH_SECONDS = 6 * 3600
FAST_REFRESH_SECONDS = 3 * 3600  # feeds that change within hours (URLhaus, ThreatFox)

# Every feed below was checked to be live and downloadable with no API key. Each one is a
# single vendor's own list, so the security-checks panel can say exactly who flagged what,
# instead of aggregates like FireHOL "level" sets that merge several vendors into one row.
# Deliberately left out: Spamhaus EDROP (merged into DROP, now empty), abuse.ch SSLBL IP list
# (empty), Darklist.de and DigitalSide (empty / unreachable), Phishing Army (re-publishes
# CERT Polska and others, so it would double-count them), PhishTank (anonymous dump removed).

Entry = tuple[str, "str | None"]  # (indicator, per-entry detail such as the malware name)


def _first_token(line: str) -> str:
    parts = line.split("#", 1)[0].split(";", 1)[0].split()
    return parts[0] if parts else ""


def parse_plain(text: str) -> Iterable[Entry]:
    """One IP / CIDR / domain / URL per line; '#' and ';' comments and trailing notes dropped."""
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#;":
            continue
        token = _first_token(line)
        if token:
            yield token, None


def parse_dshield(text: str) -> Iterable[Entry]:
    """SANS ISC block.txt: start<TAB>end<TAB>prefix-length<TAB>attacks..."""
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        cols = line.split("\t")
        if len(cols) >= 3 and cols[0].count(".") == 3:
            yield f"{cols[0]}/{cols[2]}", None


def _parse_threatfox(text: str, ioc_type: str) -> Iterable[Entry]:
    rows = csv.reader((line for line in text.splitlines() if line and not line.startswith("#")), skipinitialspace=True)
    for row in rows:
        if len(row) < 8 or row[3] != ioc_type:
            continue
        value = row[2].rsplit(":", 1)[0] if ioc_type == "ip:port" else row[2]
        malware = row[7] if row[7] and row[7] != "None" else "malware"
        threat = {"botnet_cc": "botnet C2"}.get(row[4], row[4].replace("_", " "))
        yield value.lower(), f"{malware} {threat}"


def parse_threatfox_ips(text: str) -> Iterable[Entry]:
    return _parse_threatfox(text, "ip:port")


def parse_threatfox_domains(text: str) -> Iterable[Entry]:
    return _parse_threatfox(text, "domain")


@dataclass(frozen=True)
class Feed:
    key: str
    name: str  # vendor shown in the security-checks panel
    url: str
    detail: str  # shown when flagged, unless the entry has its own detail
    kind: str  # "ip" | "domain" | "url"
    parse: Callable[[str], Iterable[Entry]] = parse_plain
    refresh: int = IP_REFRESH_SECONDS
    threat: str = ""  # short label for the URL result's threat badge


IP_FEEDS = [
    Feed("spamhaus_drop", "Spamhaus DROP", "https://www.spamhaus.org/drop/drop.txt",
         "Listed — hijacked or criminal-operated netblock", "ip"),
    Feed("dshield", "DShield (SANS ISC)", "https://feeds.dshield.org/block.txt",
         "Listed — top attacking /24 subnet", "ip", parse_dshield),
    Feed("et_compromised", "Emerging Threats", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
         "Listed — known compromised host", "ip"),
    Feed("cins_army", "CINS Army", "https://cinsscore.com/list/ci-badguys.txt",
         "Listed — poor reputation from Sentinel IPS sensors", "ip"),
    Feed("blocklist_de", "Blocklist.de", "https://lists.blocklist.de/lists/all.txt",
         "Listed — reported for attacks (SSH, mail, web, brute force)", "ip"),
    Feed("greensnow", "GreenSnow", "https://blocklist.greensnow.co/greensnow.txt",
         "Listed — seen scanning or brute-forcing", "ip"),
    Feed("binarydefense", "Binary Defense", "https://www.binarydefense.com/banlist.txt",
         "Listed — Artillery threat intelligence ban list", "ip"),
    Feed("bruteforceblocker", "BruteForceBlocker", "https://danger.rulez.sk/projects/bruteforceblocker/blist.php",
         "Listed — SSH brute-force source", "ip"),
    Feed("feodo_c2", "abuse.ch Feodo Tracker", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
         "Listed — botnet C2 server (Emotet, Dridex, QakBot…)", "ip"),
    Feed("threatfox_ip", "abuse.ch ThreatFox", "https://threatfox.abuse.ch/export/csv/ip-port/recent/",
         "Listed — malware infrastructure", "ip", parse_threatfox_ips, FAST_REFRESH_SECONDS),
    Feed("botvrij_ip", "Botvrij.eu", "https://www.botvrij.eu/data/ioclist.ip-dst.raw",
         "Listed — malicious IP from OSINT reports", "ip"),
    Feed("tor_exits", "Tor Project Exit List", "https://check.torproject.org/torbulkexitlist",
         "Listed — published Tor exit node", "ip"),
    # Proxy/VPN signals (not attacks), kept as distinct sources for the Proxy and VPN badges.
    Feed("firehol_anonymous", "FireHOL Anonymous Proxies",
         "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_anonymous.netset",
         "Listed — known open or anonymizing proxy", "ip"),
    Feed("vpn_ranges", "X4BNet VPN Ranges", "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/ipv4.txt",
         "Listed — commercial VPN provider range", "ip"),
]

URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"

DOMAIN_FEEDS = [
    Feed("threatfox_domain", "abuse.ch ThreatFox (domain)", "https://threatfox.abuse.ch/export/csv/domains/recent/",
         "Domain listed as malware infrastructure", "domain", parse_threatfox_domains, FAST_REFRESH_SECONDS),
    Feed("certpl", "CERT Polska", "https://hole.cert.pl/domains/v2/domains.txt",
         "Domain listed as phishing / fraud", "domain", threat="phishing"),
]

URL_FEEDS = [
    Feed("openphish", "OpenPhish", "https://openphish.com/feed.txt",
         "URL confirmed as an active phishing page", "url", threat="phishing"),
]


class _ListStore:
    """Parsed IP list: exact addresses in a dict (O(1) lookup, with an optional per-entry
    detail), real CIDR ranges in a list (linear scan — far fewer of them in practice)."""

    def __init__(self):
        self.exact: dict[str, str | None] = {}
        self.networks: list = []

    def load(self, entries: Iterable[Entry]):
        exact: dict[str, str | None] = {}
        networks = []
        for value, detail in entries:
            try:
                net = ipaddress.ip_network(value, strict=False)
            except ValueError:
                continue
            if net.num_addresses == 1:
                exact[str(net.network_address)] = detail
            else:
                networks.append(net)
        self.exact = exact
        self.networks = networks

    def lookup(self, ip_str: str) -> tuple[bool, str | None]:
        if ip_str in self.exact:
            return True, self.exact[ip_str]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, None
        return any(ip_obj in net for net in self.networks), None

    def contains(self, ip_str: str) -> bool:
        return self.lookup(ip_str)[0]

    def __len__(self):
        return len(self.exact) + len(self.networks)


def _normalize_url(url: str) -> str:
    return url.strip().rstrip("/").lower()


def _domain_and_parents(domain: str) -> list[str]:
    """a.b.evil.com -> [a.b.evil.com, b.evil.com, evil.com]; a listed parent covers its subdomains."""
    parts = domain.lower().strip(".").split(".")
    return [".".join(parts[i:]) for i in range(len(parts) - 1)]


class BlocklistRegistry:
    def __init__(self):
        self.lists: dict[str, _ListStore] = {f.key: _ListStore() for f in IP_FEEDS}
        self.domain_lists: dict[str, dict[str, str | None]] = {f.key: {} for f in DOMAIN_FEEDS}
        self.url_lists: dict[str, set[str]] = {f.key: set() for f in URL_FEEDS}
        self.malicious_urls: set[str] = set()
        self.malicious_domains: dict[str, str] = {}  # URLhaus: domain -> threat type
        self._loaded = False

    # ------------------------------------------------------------------ refresh

    def refresh_all(self, force: bool = False):
        jobs = [(f, force) for f in (*IP_FEEDS, *DOMAIN_FEEDS, *URL_FEEDS)]
        with ThreadPoolExecutor(max_workers=6) as pool:
            list(pool.map(lambda job: self._refresh_feed(*job), jobs))
            pool.submit(self._refresh_urlhaus, force).result()
        self._loaded = True

    def _cache_paths(self, name: str):
        return (
            os.path.join(CACHE_DIR, f"{name}.txt"),
            os.path.join(CACHE_DIR, f"{name}.meta"),
        )

    def _is_stale(self, meta_path: str, max_age: int, url: str) -> bool:
        """Stale when too old, or when the cache came from a different URL (the feed's
        source changed), so a fresh-looking file from the old source isn't reused."""
        if not os.path.exists(meta_path):
            return True
        try:
            with open(meta_path) as f:
                fetched_at, _, cached_url = f.read().strip().partition(" ")
            age = time.time() - float(fetched_at)
        except (ValueError, OSError):
            return True
        return age > max_age or cached_url != url

    def _fetch_cached(self, key: str, url: str, max_age: int, force: bool) -> str | None:
        """Downloads the feed when stale, otherwise (or when the download fails) uses the
        copy cached on disk from the last successful download."""
        data_path, meta_path = self._cache_paths(key)
        if force or self._is_stale(meta_path, max_age, url):
            try:
                resp = httpx.get(url, timeout=30, follow_redirects=True,
                                 headers={"User-Agent": "intel-threatlookup/1.0"})
                resp.raise_for_status()
                with open(data_path, "w") as f:
                    f.write(resp.text)
                with open(meta_path, "w") as f:
                    f.write(f"{time.time()} {url}")
                return resp.text
            except (httpx.HTTPError, OSError):
                pass  # network down / feed temporarily unavailable
        if os.path.exists(data_path):
            with open(data_path) as f:
                return f.read()
        return None

    def _refresh_feed(self, feed: Feed, force: bool):
        text = self._fetch_cached(feed.key, feed.url, feed.refresh, force)
        if text is None:
            return
        entries = feed.parse(text)
        if feed.kind == "ip":
            self.lists[feed.key].load(entries)
        elif feed.kind == "domain":
            self.domain_lists[feed.key] = {v.lower().strip("."): d for v, d in entries}
        else:
            self.url_lists[feed.key] = {_normalize_url(v) for v, _ in entries}

    def _refresh_urlhaus(self, force: bool):
        text = self._fetch_cached("urlhaus", URLHAUS_CSV_URL, FAST_REFRESH_SECONDS, force)
        if text is not None:
            self._load_urlhaus(text)

    def _load_urlhaus(self, text: str):
        lines = [line for line in text.splitlines() if line and not line.startswith("#")]
        urls = set()
        domains: dict[str, str] = {}
        for row in csv.reader(lines):
            if len(row) < 6:
                continue
            _id, _dateadded, url, _status, _last_online, threat = row[:6]
            if not url:
                continue
            urls.add(url)
            try:
                host = urlparse(url).hostname
                if host:
                    domains[host.lower()] = threat
            except ValueError:
                continue
        self.malicious_urls = urls
        self.malicious_domains = domains

    # ------------------------------------------------------------------- checks

    def check_ip(self, ip: str) -> dict:
        hits: list[str] = []
        details: dict[str, str] = {}
        for feed in IP_FEEDS:
            found, detail = self.lists[feed.key].lookup(ip)
            if found:
                hits.append(feed.key)
                if detail:
                    details[feed.key] = f"Listed — {detail}"
        return {
            "lists_checked": len(IP_FEEDS),
            "lists_flagged": len(hits),
            "hits": hits,
            "details": details,
            "is_tor": "tor_exits" in hits,
            "is_anon_proxy": "firehol_anonymous" in hits,
            "is_vpn": "vpn_ranges" in hits,
        }

    def check_url(self, url: str, domain: str | None) -> dict:
        """Every URL/domain vendor, clean or flagged, plus the verdict inputs for scoring."""
        normalized = _normalize_url(url)
        candidates = _domain_and_parents(domain) if domain else []
        checks: list[dict] = []

        exact = url in self.malicious_urls
        checks.append({
            "name": "abuse.ch URLhaus (exact URL)",
            "flagged": exact,
            "detail": "Confirmed on the live malicious-URL feed" if exact else "Not present on the live feed",
        })
        urlhaus_threat = self.malicious_domains.get(domain.lower()) if domain else None
        checks.append({
            "name": "abuse.ch URLhaus (domain)",
            "flagged": urlhaus_threat is not None,
            "detail": (f"Domain has hosted {urlhaus_threat} payloads" if urlhaus_threat is not None
                       else "Domain not associated with known malware distribution"),
        })

        url_hit = False
        threat: str | None = urlhaus_threat
        for feed in URL_FEEDS:
            flagged = normalized in self.url_lists[feed.key]
            url_hit = url_hit or flagged
            if flagged and not threat:
                threat = feed.threat or None
            checks.append({"name": feed.name, "flagged": flagged, "detail": feed.detail if flagged else "Not listed"})

        domain_hit = False
        for feed in DOMAIN_FEEDS:
            listed = next((d for d in candidates if d in self.domain_lists[feed.key]), None)
            flagged = listed is not None
            detail = self.domain_lists[feed.key].get(listed) if flagged else None
            domain_hit = domain_hit or flagged
            if flagged and not threat:
                threat = detail or feed.threat or None
            checks.append({
                "name": feed.name,
                "flagged": flagged,
                "detail": (f"Domain listed — {detail}" if detail else feed.detail) if flagged else "Not listed",
            })

        return {
            "exact_match": exact or url_hit,
            "domain_match": urlhaus_threat is not None or domain_hit,
            "threat_type": threat,
            "checks": checks,
        }

    @property
    def stats(self) -> dict:
        return (
            {key: len(store) for key, store in self.lists.items()}
            | {key: len(entries) for key, entries in self.domain_lists.items()}
            | {key: len(entries) for key, entries in self.url_lists.items()}
            | {"urlhaus_urls": len(self.malicious_urls)}
        )


def build_ip_security_checks(result: dict) -> list[dict]:
    """One entry per IP vendor, always present (clean or flagged) — the per-vendor
    breakdown behind the aggregate malicious score."""
    return [
        {
            "name": feed.name,
            "flagged": feed.key in result["hits"],
            "detail": result["details"].get(feed.key, feed.detail) if feed.key in result["hits"] else "Not listed",
        }
        for feed in IP_FEEDS
    ]


registry = BlocklistRegistry()
