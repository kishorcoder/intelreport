export interface SecurityCheck {
  name: string;
  flagged: boolean;
  detail: string;
}

export interface IPLookup {
  id: number;
  ip: string;
  isp: string | null;
  org: string | null;
  asn: string | null;
  country: string | null;
  country_code: string | null;
  city: string | null;
  region: string | null;
  timezone: string | null;
  is_proxy: boolean;
  is_vpn: boolean;
  is_hosting: boolean;
  is_tor: boolean;
  is_mobile: boolean;
  /** Not routed on the public internet: RFC 1918 private, loopback, CGNAT, … */
  is_private: boolean | null;
  address_type: string | null;
  address_range: string | null;
  malicious_score: number;
  lists_checked: number;
  lists_flagged: number;
  blocklist_hits: string[];
  rdap_org: string | null;
  rdap_network: string | null;
  reverse_dns: string | null;
  security_checks: SecurityCheck[];
  fetched_at: string;
}

export interface UrlLookup {
  id: number;
  url: string;
  domain: string | null;
  host_ip: string | null;
  is_malicious: boolean;
  exact_match_verified: boolean;
  threat_type: string | null;
  malicious_score: number;
  host_ip_score: number;
  host_rdap_org: string | null;
  domain_registered_at: string | null;
  domain_expires_at: string | null;
  domain_last_changed_at: string | null;
  domain_dates_source: string | null;
  domain_whois_raw: string | null;
  security_checks: SecurityCheck[];
  checked_at: string;
}

export interface FileLookup {
  id: number;
  sha256: string;
  sha1: string | null;
  md5: string | null;
  filename: string | null;
  size_bytes: number;
  is_pe: boolean;
  pe_company_name: string | null;
  pe_copyright: string | null;
  pe_product_name: string | null;
  pe_original_filename: string | null;
  pe_file_description: string | null;
  pe_file_version: string | null;
  is_signed: boolean;
  signer_name: string | null;
  entropy: number | null;
  risk_score: number;
  risk_factors: string[];
  security_checks: SecurityCheck[];
  first_seen_at: string;
  last_seen_at: string;
  submission_count: number;
}

export type HashLookupResult =
  | ({ found: true } & FileLookup)
  | { found: false; sha256: string; note: string };

export type HistoryItemType = 'ip' | 'url' | 'file';

export interface HistoryItem {
  type: HistoryItemType;
  key: string;
  score: number;
  at: string;
  detail: IPLookup | UrlLookup | FileLookup;
}
