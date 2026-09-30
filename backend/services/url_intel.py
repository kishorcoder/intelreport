import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx
from sqlalchemy.orm import Session

import models
from services.blocklists import registry
from services.domain_utils import registrable_domain as _registrable_domain
from services.ip_intel import lookup_ip
from services.whois_intel import fetch_whois, parse_whois_dates

URL_CACHE_MAX_AGE_HOURS = 24


def _resolve_host_ip(domain: str) -> str | None:
    try:
        return socket.gethostbyname(domain)
    except (socket.gaierror, UnicodeError):
        return None


def _fetch_domain_rdap(hostname: str) -> dict:
    registrable = _registrable_domain(hostname)
    if not registrable:
        return {}
    try:
        resp = httpx.get(f"https://rdap.org/domain/{registrable}", timeout=10, follow_redirects=True)
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPError:
        return {}


def _parse_rdap_date(date_str: str | None) -> datetime | None:
    if not date_str:
        return None
    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except ValueError:
        return None


def _domain_rdap_dates(rdap: dict) -> dict:
    events = {e.get("eventAction"): e.get("eventDate") for e in rdap.get("events", [])}
    return {
        "registered_at": _parse_rdap_date(events.get("registration")),
        "expires_at": _parse_rdap_date(events.get("expiration")),
        # RDAP has no distinct "renewal" event — "last changed" is the registry's most
        # recent update timestamp, which in practice is what a renewal shows up as.
        "last_changed_at": _parse_rdap_date(events.get("last changed")),
    }


def _domain_registration_info(hostname: str) -> dict:
    """RDAP first (structured, fast, well-supported by the big gTLDs) — then
    fall back to a raw WHOIS crawl for whatever RDAP couldn't answer, since
    plenty of ccTLD registries still don't run an RDAP server at all. The raw
    WHOIS text is always kept when fetched, so it doesn't need re-crawling
    later even if nothing useful was parsed out of it this time."""
    registrable = _registrable_domain(hostname)
    dates = _domain_rdap_dates(_fetch_domain_rdap(hostname)) if registrable else {}
    used_rdap = bool(dates.get("registered_at") or dates.get("expires_at") or dates.get("last_changed_at"))

    whois_raw = None
    used_whois = False
    missing = {"registered_at", "expires_at", "last_changed_at"} - {k for k, v in dates.items() if v}
    if registrable and missing:
        whois_raw = fetch_whois(registrable)
        if whois_raw:
            whois_dates = parse_whois_dates(whois_raw)
            for key, value in whois_dates.items():
                if not dates.get(key):
                    dates[key] = value
                    used_whois = True

    source = "+".join(s for s, used in (("rdap", used_rdap), ("whois", used_whois)) if used) or None
    return {**dates, "source": source, "whois_raw": whois_raw}


def _build_url_security_checks(phish: dict, ip_row: "models.IPLookup | None") -> list[dict]:
    """URL/domain vendors first, then every vendor checked for the host's IP."""
    checks = list(phish["checks"])
    if ip_row is not None and ip_row.security_checks:
        checks.extend(ip_row.security_checks)
    return checks


def _url_score(phish: dict, host_ip_score: float) -> float:
    if phish["exact_match"]:
        return 100.0
    if phish["domain_match"]:
        return 80.0
    # No URL/domain listing — treat elevated underlying-IP reputation as a soft signal,
    # capped well below a confirmed malicious verdict.
    return min(host_ip_score, 35.0)


def lookup_url(db: Session, url: str, force_refresh: bool = False) -> models.UrlLookup:
    existing = db.query(models.UrlLookup).filter(models.UrlLookup.url == url).first()
    if existing and not force_refresh:
        age_hours = (datetime.now(timezone.utc) - existing.checked_at.replace(tzinfo=timezone.utc)).total_seconds() / 3600
        if age_hours < URL_CACHE_MAX_AGE_HOURS:
            return existing

    parsed = urlparse(url if "://" in url else f"http://{url}")
    domain = parsed.hostname

    phish = registry.check_url(url, domain)
    host_ip = _resolve_host_ip(domain) if domain else None
    domain_info = _domain_registration_info(domain) if domain else {}

    host_ip_score = 0.0
    host_rdap_org = None
    ip_row = None
    if host_ip:
        try:
            ip_row = lookup_ip(db, host_ip)
            host_ip_score = ip_row.malicious_score
            host_rdap_org = ip_row.rdap_org
        except Exception:
            host_ip_score = 0.0
            ip_row = None

    score = _url_score(phish, host_ip_score)

    row = existing or models.UrlLookup(url=url)
    row.domain = domain
    row.host_ip = host_ip
    row.is_malicious = phish["exact_match"] or phish["domain_match"]
    row.exact_match_verified = phish["exact_match"]
    row.threat_type = phish.get("threat_type")
    row.malicious_score = round(score, 1)
    row.host_ip_score = host_ip_score
    row.host_rdap_org = host_rdap_org
    row.domain_registered_at = domain_info.get("registered_at")
    row.domain_expires_at = domain_info.get("expires_at")
    row.domain_last_changed_at = domain_info.get("last_changed_at")
    row.domain_dates_source = domain_info.get("source")
    if domain_info.get("whois_raw"):
        row.domain_whois_raw = domain_info["whois_raw"]
    row.security_checks = _build_url_security_checks(phish, ip_row)
    row.checked_at = datetime.now(timezone.utc)

    if not existing:
        db.add(row)
    db.commit()
    db.refresh(row)
    return row


def backfill_security_checks(db: Session) -> int:
    """Recomputes every cached row's vendor checks and verdict on startup, from the
    stored url/domain/host_ip plus the in-memory feeds and the host IP's own
    (already-recomputed) row — no external calls needed."""
    rows = db.query(models.UrlLookup).all()
    for row in rows:
        phish = registry.check_url(row.url, row.domain)
        ip_row = db.query(models.IPLookup).filter(models.IPLookup.ip == row.host_ip).first() if row.host_ip else None
        row.host_ip_score = ip_row.malicious_score if ip_row is not None else (row.host_ip_score or 0.0)
        row.is_malicious = phish["exact_match"] or phish["domain_match"]
        row.exact_match_verified = phish["exact_match"]
        row.threat_type = phish.get("threat_type")
        row.malicious_score = round(_url_score(phish, row.host_ip_score), 1)
        row.security_checks = _build_url_security_checks(phish, ip_row)
    if rows:
        db.commit()
    return len(rows)
