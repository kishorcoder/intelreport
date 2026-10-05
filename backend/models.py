from sqlalchemy import Column, Integer, String, Boolean, DateTime, Float, JSON, Text
from database import Base


class IPLookup(Base):
    __tablename__ = "ip_lookups"

    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String, unique=True, index=True, nullable=False)
    isp = Column(String, nullable=True)
    org = Column(String, nullable=True)
    asn = Column(String, nullable=True)
    country = Column(String, nullable=True)
    country_code = Column(String, nullable=True)
    city = Column(String, nullable=True)
    region = Column(String, nullable=True)
    timezone = Column(String, nullable=True)
    is_proxy = Column(Boolean, default=False)
    is_vpn = Column(Boolean, default=False)
    is_hosting = Column(Boolean, default=False)
    is_tor = Column(Boolean, default=False)
    is_mobile = Column(Boolean, default=False)
    # Not routed on the public internet (RFC 1918 private, loopback, CGNAT, …)
    is_private = Column(Boolean, default=False)
    address_type = Column(String, nullable=True)  # e.g. "Private network (RFC 1918)"
    address_range = Column(String, nullable=True)  # e.g. "192.168.0.0/16"
    malicious_score = Column(Float, default=0.0)
    lists_checked = Column(Integer, default=0)
    lists_flagged = Column(Integer, default=0)
    blocklist_hits = Column(JSON, default=list)
    rdap_org = Column(String, nullable=True)
    rdap_network = Column(String, nullable=True)
    reverse_dns = Column(String, nullable=True)
    raw_source_json = Column(JSON, nullable=True)
    security_checks = Column(JSON, default=list)
    fetched_at = Column(DateTime, nullable=False)


class UrlLookup(Base):
    __tablename__ = "url_lookups"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, index=True, nullable=False)
    domain = Column(String, index=True, nullable=True)
    host_ip = Column(String, nullable=True)
    is_malicious = Column(Boolean, default=False)
    exact_match_verified = Column(Boolean, default=False)
    threat_type = Column(String, nullable=True)
    malicious_score = Column(Float, default=0.0)
    host_ip_score = Column(Float, default=0.0)
    host_rdap_org = Column(String, nullable=True)
    domain_registered_at = Column(DateTime, nullable=True)
    domain_expires_at = Column(DateTime, nullable=True)
    domain_last_changed_at = Column(DateTime, nullable=True)
    domain_dates_source = Column(String, nullable=True)  # "rdap", "whois", or "rdap+whois"
    domain_whois_raw = Column(Text, nullable=True)
    security_checks = Column(JSON, default=list)
    checked_at = Column(DateTime, nullable=False)


class FileLookup(Base):
    __tablename__ = "file_lookups"

    id = Column(Integer, primary_key=True, index=True)
    sha256 = Column(String, unique=True, index=True, nullable=False)
    sha1 = Column(String, nullable=True)
    md5 = Column(String, nullable=True)
    filename = Column(String, nullable=True)
    size_bytes = Column(Integer, nullable=True)
    is_pe = Column(Boolean, default=False)
    pe_company_name = Column(String, nullable=True)
    pe_copyright = Column(String, nullable=True)
    pe_product_name = Column(String, nullable=True)
    pe_original_filename = Column(String, nullable=True)
    pe_file_description = Column(String, nullable=True)
    pe_file_version = Column(String, nullable=True)
    is_signed = Column(Boolean, default=False)
    signer_name = Column(String, nullable=True)
    entropy = Column(Float, nullable=True)
    risk_score = Column(Float, default=0.0)
    risk_factors = Column(JSON, default=list)
    security_checks = Column(JSON, default=list)
    first_seen_at = Column(DateTime, nullable=False)
    last_seen_at = Column(DateTime, nullable=False)
    submission_count = Column(Integer, default=1)
