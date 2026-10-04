import logging
import socket
from datetime import datetime, timezone

import httpx
from sqlalchemy.orm import Session

import models
from services.blocklists import registry, build_ip_security_checks
from services.domain_utils import registrable_domain

IP_API_FIELDS = (
    "status,message,country,countryCode,region,regionName,city,timezone,"
    "isp,org,as,mobile,proxy,hosting,query"
)
IP_CACHE_MAX_AGE_HOURS = 24

logger = logging.getLogger("intel")


def _fetch_ip_api(ip: str) -> dict:
    """Geolocation is a nice-to-have: if ip-api.com is slow, down, or rate-limiting us
    (45 requests/min, shared by every visitor since all lookups come from this server),
    return {} so the lookup still succeeds with its vendor checks instead of failing."""
    url = f"http://ip-api.com/json/{ip}?fields={IP_API_FIELDS}"
    try:
        resp = httpx.get(url, timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except (httpx.HTTPError, ValueError) as e:
        logger.warning("ip-api lookup failed for %s: %s", ip, e)
        return {}
    return data if data.get("status") == "success" else {}


def _fetch_rdap(ip: str) -> dict:
    try:
        resp = httpx.get(f"https://rdap.org/ip/{ip}", timeout=10, follow_redirects=True)
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPError:
        return {}


def _reverse_dns(ip: str) -> str | None:
    """PTR lookup via the system resolver — no external API, keyless by
    nature. Most residential/cloud IPs have one; plenty of others don't.
    PTR records are full hostnames (e.g. "ec2-1-2-3-4.compute.amazonaws.com"),
    so this reduces to just the registrable domain for display — same
    eTLD+1 logic already used for the RDAP/WHOIS domain lookups."""
    try:
        hostname, _aliases, _ips = socket.gethostbyaddr(ip)
    except (socket.herror, socket.gaierror, UnicodeError):
        return None
    return registrable_domain(hostname) or hostname


def _rdap_org(rdap: dict) -> str | None:
    for entity in rdap.get("entities", []):
        if "registrant" in entity.get("roles", []) or "administrative" in entity.get("roles", []):
            vcard = entity.get("vcardArray")
            if vcard and len(vcard) > 1:
                for field in vcard[1]:
                    if field[0] == "fn":
                        return field[3]
    return None


def lookup_ip(db: Session, ip: str, force_refresh: bool = False) -> models.IPLookup:
    existing = db.query(models.IPLookup).filter(models.IPLookup.ip == ip).first()
    if existing and not force_refresh:
        age_hours = (datetime.now(timezone.utc) - existing.fetched_at.replace(tzinfo=timezone.utc)).total_seconds() / 3600
        # A row saved while geolocation was unavailable is refetched rather than served
        # from cache for a whole day with its location missing.
        if age_hours < IP_CACHE_MAX_AGE_HOURS and existing.country:
            return existing

    geo = _fetch_ip_api(ip)
    rdap = _fetch_rdap(ip)
    reverse_dns = _reverse_dns(ip)
    block_result = registry.check_ip(ip)

    lists_checked = block_result["lists_checked"]
    lists_flagged = block_result["lists_flagged"]
    score = round((lists_flagged / lists_checked) * 100, 1) if lists_checked else 0.0

    row = existing or models.IPLookup(ip=ip)
    if geo:  # on a geolocation outage, keep whatever an earlier lookup stored
        row.isp = geo.get("isp")
        row.org = geo.get("org")
        row.asn = geo.get("as")
        row.country = geo.get("country")
        row.country_code = geo.get("countryCode")
        row.city = geo.get("city")
        row.region = geo.get("regionName")
        row.timezone = geo.get("timezone")
        row.is_hosting = bool(geo.get("hosting"))
        row.is_mobile = bool(geo.get("mobile"))
    geo_proxy = bool(geo.get("proxy")) if geo else bool(existing and existing.is_proxy)
    row.is_proxy = geo_proxy or block_result["is_anon_proxy"]
    row.is_vpn = block_result["is_vpn"]
    row.is_tor = block_result["is_tor"]
    row.malicious_score = score
    row.lists_checked = lists_checked
    row.lists_flagged = lists_flagged
    row.blocklist_hits = block_result["hits"]
    row.security_checks = build_ip_security_checks(block_result)
    row.rdap_org = _rdap_org(rdap)
    row.rdap_network = rdap.get("name")
    row.reverse_dns = reverse_dns
    if geo:
        row.raw_source_json = {"ip_api": geo}
    row.fetched_at = datetime.now(timezone.utc)

    if not existing:
        db.add(row)
    db.commit()
    db.refresh(row)
    return row


def backfill_security_checks(db: Session) -> int:
    """Recomputes every cached row's vendor checks on startup, so cached results
    pick up vendor-feed changes (new vendors, refreshed lists) straight away
    instead of after their 24h cache expires. Every value here derives from the
    stored IP plus the in-memory feeds — no external calls, cheap to run."""
    rows = db.query(models.IPLookup).all()
    for row in rows:
        block_result = registry.check_ip(row.ip)
        lists_checked = block_result["lists_checked"]
        lists_flagged = block_result["lists_flagged"]
        row.is_proxy = row.is_proxy or block_result["is_anon_proxy"]
        row.is_vpn = block_result["is_vpn"]
        row.malicious_score = round((lists_flagged / lists_checked) * 100, 1) if lists_checked else 0.0
        row.lists_checked = lists_checked
        row.lists_flagged = lists_flagged
        row.blocklist_hits = block_result["hits"]
        row.security_checks = build_ip_security_checks(block_result)
    if rows:
        db.commit()
    return len(rows)


def backfill_reverse_dns(db: Session) -> int:
    """Recomputes reverse_dns for every row on every startup — deliberately
    unconditional, not just IS NULL. DNS lookups are fast and row counts here
    are small, and this way any future change to the PTR-reduction logic (or
    a PTR record that gets added/changed after the fact) self-heals on the
    next restart instead of needing yet another one-off backfill."""
    rows = db.query(models.IPLookup).all()
    for row in rows:
        row.reverse_dns = _reverse_dns(row.ip)
    if rows:
        db.commit()
    return len(rows)
