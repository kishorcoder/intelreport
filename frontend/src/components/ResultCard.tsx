import {
  Globe2, ShieldAlert, EyeOff, Server, MapPin, Building2, Hash, FileSignature, Copyright,
  Calendar, CalendarClock, CalendarX2, ShieldCheck, ShieldX, ChevronDown,
} from 'lucide-react';
import { useEffect, useRef, useState, type ReactNode } from 'react';
import type { FileLookup, IPLookup, SecurityCheck, UrlLookup } from '../lib/types';
import { GlassCard } from './GlassCard';

// Converts an ISO 3166-1 alpha-2 code ("US") into its flag emoji by mapping
// each letter to a Unicode regional-indicator symbol — no image asset needed.
function countryFlagEmoji(countryCode: string | null | undefined): string {
  if (!countryCode || countryCode.length !== 2) return '';
  const codePoints = [...countryCode.toUpperCase()].map((c) => 0x1f1e6 + (c.charCodeAt(0) - 65));
  return String.fromCodePoint(...codePoints);
}

function formatRdapDate(iso: string | null): string | null {
  if (!iso) return null;
  return new Date(iso).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
}

// Whole-years-and-months age of a domain, from its RDAP registration date to now.
function domainAge(iso: string | null): string | null {
  if (!iso) return null;
  const then = new Date(iso);
  const now = new Date();
  let months = (now.getFullYear() - then.getFullYear()) * 12 + (now.getMonth() - then.getMonth());
  if (now.getDate() < then.getDate()) months -= 1;
  if (months < 0) return null;
  const years = Math.floor(months / 12);
  const remMonths = months % 12;
  if (years === 0) return `${remMonths} month${remMonths === 1 ? '' : 's'}`;
  if (remMonths === 0) return `${years} year${years === 1 ? '' : 's'}`;
  return `${years} year${years === 1 ? '' : 's'}, ${remMonths} month${remMonths === 1 ? '' : 's'}`;
}

function scoreColor(score: number): string {
  if (score >= 60) return 'var(--risk-high)';
  if (score >= 30) return 'var(--risk-medium)';
  if (score > 0) return 'var(--risk-low)';
  return 'var(--risk-clean)';
}

// Animates the ring fill + number counting up from 0 to `score` whenever the
// score changes (new lookup), instead of just snapping to the final value.
function useAnimatedScore(score: number, duration = 900) {
  const [display, setDisplay] = useState(0);
  const frame = useRef<number>(0);

  useEffect(() => {
    const start = performance.now();
    const from = 0;
    cancelAnimationFrame(frame.current);

    function tick(now: number) {
      const t = Math.min((now - start) / duration, 1);
      const eased = 1 - Math.pow(1 - t, 3); // ease-out cubic
      setDisplay(from + (score - from) * eased);
      if (t < 1) frame.current = requestAnimationFrame(tick);
    }
    frame.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame.current);
  }, [score, duration]);

  return display;
}

export function ScoreBadge({
  score, label, size = 64, stacked = false,
}: { score: number; label: string; size?: number; stacked?: boolean }) {
  const color = scoreColor(score);
  const animated = useAnimatedScore(score);

  const strokeWidth = Math.max(4, Math.round(size / 16));
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference * (1 - animated / 100);

  return (
    <div
      style={{
        display: 'flex', flexDirection: stacked ? 'column' : 'row', alignItems: 'center', gap: 12,
        ...(stacked ? { textAlign: 'center' } : { marginLeft: 'auto', flexShrink: 0 }),
      }}
    >
      <div style={{ position: 'relative', width: size, height: size, filter: `drop-shadow(0 0 8px ${color}55)`, flexShrink: 0 }}>
        <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
          <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="rgba(255,255,255,0.1)" strokeWidth={strokeWidth} />
          <circle
            cx={size / 2} cy={size / 2} r={radius} fill="none"
            stroke={color} strokeWidth={strokeWidth} strokeLinecap="round"
            strokeDasharray={circumference} strokeDashoffset={offset}
            style={{ transition: 'stroke 0.3s ease' }}
          />
        </svg>
        <div
          style={{
            position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: Math.round(size / 4), fontWeight: 800, color, fontFamily: 'var(--font-mono)',
          }}
        >
          {Math.round(animated)}%
        </div>
      </div>
      <div>
        <div style={{ fontSize: 13, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: 0.5, fontWeight: 700 }}>{label}</div>
        <div style={{ fontSize: 15, color: 'var(--text-mid)', marginTop: 2 }}>
          {score === 0 ? 'No indicators found' : score < 30 ? 'Low risk signal' : score < 60 ? 'Elevated risk' : 'High risk'}
        </div>
      </div>
    </div>
  );
}

// The dedicated right-hand 30%-width column every result card gives to its
// risk ring, so the score reads as its own panel rather than a small badge
// competing with the header text for space.
function ScoreColumn({ children }: { children: ReactNode }) {
  return (
    <div
      style={{
        width: '30%', flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center',
        borderLeft: '1px solid var(--glass-border)', padding: '8px 0 8px 24px',
      }}
    >
      {children}
    </div>
  );
}

// A separate container below the main detail card, listing every vendor
// checked — clean or flagged — with the reason when flagged. Never filters
// out clean vendors: seeing "0 of 14 flagged" is as meaningful as seeing
// which ones tripped. Flagged vendors are listed first.
export function SecurityChecksCard({ checks }: { checks: SecurityCheck[] | undefined | null }) {
  if (!checks || checks.length === 0) return null;
  const flaggedCount = checks.filter((c) => c.flagged).length;
  const ordered = [...checks].sort((a, b) => Number(b.flagged) - Number(a.flagged));

  return (
    <GlassCard style={{ marginTop: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14, flexWrap: 'wrap', gap: 8 }}>
        <div style={{ fontSize: 11, color: 'var(--text-dim)', fontWeight: 700, letterSpacing: 0.5, textTransform: 'uppercase' }}>
          Security Checks
        </div>
        <div style={{ fontSize: 12, fontWeight: 700, color: flaggedCount > 0 ? 'var(--risk-high)' : 'var(--risk-clean)' }}>
          {flaggedCount} of {checks.length} flagged
        </div>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))', gap: 10 }}>
        {ordered.map((c, i) => (
          <div
            key={i}
            style={{
              display: 'flex', gap: 10, padding: '10px 12px', borderRadius: 10,
              background: c.flagged ? 'rgba(238,27,36,0.08)' : 'rgba(74,222,128,0.06)',
              border: `1px solid ${c.flagged ? 'rgba(238,27,36,0.25)' : 'rgba(74,222,128,0.18)'}`,
            }}
          >
            {c.flagged ? (
              <ShieldX size={16} color="var(--risk-high)" style={{ flexShrink: 0, marginTop: 1 }} />
            ) : (
              <ShieldCheck size={16} color="var(--risk-clean)" style={{ flexShrink: 0, marginTop: 1 }} />
            )}
            <div style={{ minWidth: 0 }}>
              <div style={{ fontSize: 12.5, fontWeight: 700, color: c.flagged ? 'var(--risk-high)' : 'var(--text-hi)' }}>
                {c.name}
              </div>
              <div style={{ fontSize: 11.5, color: 'var(--text-mid)', marginTop: 2 }}>{c.detail}</div>
            </div>
          </div>
        ))}
      </div>
    </GlassCard>
  );
}

// The raw record from the WHOIS crawl fallback (services/whois_intel.py) —
// saved to the DB the first time it's fetched and shown here so it's never
// just silently stored; only rendered when we actually had to crawl it.
export function WhoisRawCard({ raw }: { raw: string | null | undefined }) {
  const [expanded, setExpanded] = useState(false);
  if (!raw) return null;

  return (
    <GlassCard style={{ marginTop: 16 }}>
      <button
        onClick={() => setExpanded((e) => !e)}
        style={{
          display: 'flex', alignItems: 'center', gap: 6, background: 'none', border: 'none',
          color: 'var(--text-mid)', fontSize: 11, fontWeight: 700, letterSpacing: 0.5, textTransform: 'uppercase',
          cursor: 'pointer', padding: 0, width: '100%', textAlign: 'left',
        }}
      >
        <ChevronDown size={13} style={{ transform: expanded ? 'rotate(180deg)' : undefined, transition: 'transform 0.15s' }} />
        Raw WHOIS Record
      </button>
      {expanded && (
        <pre
          style={{
            marginTop: 12, padding: 12, borderRadius: 10, background: 'rgba(0,0,0,0.3)',
            border: '1px solid var(--glass-border)', fontSize: 11, lineHeight: 1.6, color: 'var(--text-mid)',
            fontFamily: 'var(--font-mono)', whiteSpace: 'pre-wrap', wordBreak: 'break-word',
            maxHeight: 320, overflowY: 'auto',
          }}
        >
          {raw}
        </pre>
      )}
    </GlassCard>
  );
}

function Flag({ active, label }: { active: boolean; label: string }) {
  if (!active) return null;
  return (
    <span
      style={{
        fontSize: 12.5, fontWeight: 700, padding: '5px 12px', borderRadius: 999,
        color: 'var(--risk-medium)', border: '1px solid rgba(249,115,22,0.4)',
        background: 'linear-gradient(155deg, rgba(249,115,22,0.22), rgba(249,115,22,0.06))',
        backdropFilter: 'blur(10px) saturate(160%)',
        WebkitBackdropFilter: 'blur(10px) saturate(160%)',
        boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.12), 0 2px 10px -4px rgba(249,115,22,0.5)',
      }}
    >
      {label}
    </span>
  );
}

// Unlike Flag, this always renders — detected AND not-detected are both
// meaningful facts for network-identity checks, so it shouldn't disappear
// just because the answer is "no".
//
// `risk` switches on the red/green scheme (for Tor/VPN/Proxy, where "yes"
// is an anonymization risk signal worth flagging red and "no" is reassuring
// green). Non-risk flags (hosting, mobile) keep the neutral orange/grey look.
function StatusFlag({ active, label, risk = false }: { active: boolean; label: string; risk?: boolean }) {
  const color = risk
    ? active ? 'var(--risk-high)' : 'var(--risk-clean)'
    : active ? 'var(--risk-medium)' : 'var(--text-dim)';
  const rgb = risk ? (active ? '238,27,36' : '74,222,128') : (active ? '249,115,22' : '255,255,255');
  const border = risk
    ? active ? 'rgba(238,27,36,0.45)' : 'rgba(74,222,128,0.4)'
    : active ? 'rgba(249,115,22,0.4)' : 'rgba(255,255,255,0.12)';
  return (
    <span
      style={{
        display: 'inline-flex', alignItems: 'center', gap: 6,
        fontSize: 12.5, fontWeight: 700, padding: '5px 12px', borderRadius: 999,
        color, border: `1px solid ${border}`,
        background: `rgba(${rgb},0.12)`,
      }}
    >
      <span style={{ width: 6, height: 6, borderRadius: '50%', flexShrink: 0, background: color }} />
      {label}: {active ? 'Yes' : 'No'}
    </span>
  );
}

// Roomier spacing for the main detail cards (IP / URL / file), about 30% taller
// than the compact layout.
const DETAIL_CARD_PADDING = '32px 20px';
const DETAIL_ROW_GAP = 16;
const FLAGS_ROW = { display: 'flex', gap: 6, marginTop: 16, marginBottom: 28, flexWrap: 'wrap' } as const;

function Field({ icon: Icon, label, value }: { icon: typeof Globe2; label: string; value: ReactNode }) {
  return (
    <div style={{ display: 'flex', gap: 8, alignItems: 'flex-start' }}>
      <Icon size={16} color="var(--text-dim)" style={{ marginTop: 2, flexShrink: 0 }} />
      <div>
        <div style={{ fontSize: 11.5, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: 0.4, marginBottom: 3 }}>{label}</div>
        <div style={{ fontSize: 15, color: 'var(--text-hi)', fontWeight: 600, overflowWrap: 'anywhere' }}>{value || '—'}</div>
      </div>
    </div>
  );
}

export function IpResultCard({ data }: { data: IPLookup }) {
  return (
    <>
    <GlassCard style={{ padding: DETAIL_CARD_PADDING }}>
      <div style={{ display: 'flex', gap: 24 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 12.5, color: 'var(--text-dim)', fontWeight: 600, letterSpacing: 0.5, marginBottom: 6 }}>IP ADDRESS</div>
          <div style={{ fontSize: 24, fontWeight: 700, fontFamily: 'var(--font-mono)' }}>{data.ip}</div>
          <div style={FLAGS_ROW}>
            <StatusFlag active={data.is_tor} label="TOR" risk />
            <StatusFlag active={data.is_vpn} label="VPN" risk />
            <StatusFlag active={data.is_proxy} label="PROXY" risk />
            <StatusFlag active={data.is_hosting} label="HOSTING / DATACENTER" />
            <StatusFlag active={data.is_mobile} label="MOBILE CARRIER" />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', columnGap: 14, rowGap: DETAIL_ROW_GAP, marginBottom: 22 }}>
            <Field icon={Building2} label="ISP" value={data.isp} />
            <Field icon={Server} label="Organization" value={data.org} />
            <Field icon={Hash} label="ASN" value={data.asn} />
            <Field icon={Globe2} label="Domain Name" value={data.reverse_dns} />
            <Field icon={Building2} label="RDAP Registrant" value={data.rdap_org} />
            <Field icon={Server} label="RDAP Network" value={data.rdap_network} />
            <Field
              icon={Globe2}
              label="Country"
              value={
                data.country ? (
                  <>
                    <span style={{ fontSize: 30, lineHeight: '18px', display: 'inline-block', verticalAlign: 'middle', margin: '-6px 8px -4px 0' }}>
                      {countryFlagEmoji(data.country_code)}
                    </span>
                    {data.country}
                  </>
                ) : null
              }
            />
            <Field icon={MapPin} label="City" value={[data.city, data.region].filter(Boolean).join(', ')} />
          </div>
        </div>

        <ScoreColumn>
          <ScoreBadge score={data.malicious_score} label="Malicious Flagging" size={144} stacked />
        </ScoreColumn>
      </div>
    </GlassCard>
    <SecurityChecksCard checks={data.security_checks} />
    </>
  );
}

export function UrlResultCard({ data }: { data: UrlLookup }) {
  return (
    <>
    <GlassCard style={{ padding: DETAIL_CARD_PADDING }}>
      <div style={{ display: 'flex', gap: 24 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 12.5, color: 'var(--text-dim)', fontWeight: 600, letterSpacing: 0.5, marginBottom: 6 }}>URL</div>
          <div style={{ fontSize: 18, fontWeight: 700, fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>{data.url}</div>
          <div style={FLAGS_ROW}>
            {data.exact_match_verified && <Flag active label="CONFIRMED MALICIOUS (URLhaus)" />}
            {data.threat_type && <Flag active label={data.threat_type.toUpperCase()} />}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', columnGap: 14, rowGap: DETAIL_ROW_GAP, marginBottom: data.domain_registered_at ? DETAIL_ROW_GAP : 0 }}>
            <Field icon={Globe2} label="Domain" value={data.domain} />
            <Field icon={Server} label="Host IP" value={data.host_ip} />
            {data.host_rdap_org && <Field icon={Building2} label="Host IP Network (RDAP)" value={data.host_rdap_org} />}
          </div>

          {data.domain_registered_at && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', columnGap: 14, rowGap: DETAIL_ROW_GAP }}>
              <Field icon={Calendar} label="Domain Registered" value={formatRdapDate(data.domain_registered_at)} />
              <Field icon={Calendar} label="Domain Age" value={domainAge(data.domain_registered_at)} />
              <Field icon={CalendarClock} label="Last Renewed / Updated" value={formatRdapDate(data.domain_last_changed_at)} />
              <Field icon={CalendarX2} label="Expires" value={formatRdapDate(data.domain_expires_at)} />
            </div>
          )}
        </div>

        <ScoreColumn>
          <ScoreBadge score={data.malicious_score} label="Malicious Flagging" size={144} stacked />
        </ScoreColumn>
      </div>
    </GlassCard>
    <SecurityChecksCard checks={data.security_checks} />
    <WhoisRawCard raw={data.domain_whois_raw} />
    </>
  );
}

export function FileResultCard({ data }: { data: FileLookup }) {
  return (
    <>
    <GlassCard style={{ padding: DETAIL_CARD_PADDING }}>
      <div style={{ display: 'flex', gap: 24 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 12.5, color: 'var(--text-dim)', fontWeight: 600, letterSpacing: 0.5, marginBottom: 6 }}>FILE</div>
          <div style={{ fontSize: 21, fontWeight: 700 }}>{data.filename || 'unnamed'}</div>
          <div style={{ fontSize: 13.5, color: 'var(--text-dim)', marginTop: 4 }}>
            {data.size_bytes.toLocaleString()} bytes · {data.is_pe ? 'PE executable' : 'non-PE file'}
            {data.submission_count > 1 && ` · seen ${data.submission_count}× before`}
          </div>
          <div style={FLAGS_ROW}>
            <Flag active={!data.is_signed} label="UNSIGNED" />
            {data.is_signed && (
              <span
                style={{
                  fontSize: 12.5, fontWeight: 700, padding: '5px 12px', borderRadius: 999,
                  color: 'var(--risk-clean)', border: '1px solid rgba(74,222,128,0.4)',
                  background: 'linear-gradient(155deg, rgba(74,222,128,0.22), rgba(74,222,128,0.06))',
                  backdropFilter: 'blur(10px) saturate(160%)',
                  WebkitBackdropFilter: 'blur(10px) saturate(160%)',
                  boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.12), 0 2px 10px -4px rgba(74,222,128,0.5)',
                }}
              >
                SIGNED{data.signer_name ? `: ${data.signer_name}` : ''}
              </span>
            )}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 8, marginBottom: 16 }}>
            <Field icon={Hash} label="SHA256" value={data.sha256} />
            <Field icon={Hash} label="SHA1" value={data.sha1} />
            <Field icon={Hash} label="MD5" value={data.md5} />
          </div>

          {data.is_pe && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', columnGap: 14, rowGap: DETAIL_ROW_GAP, marginBottom: 22 }}>
              <Field icon={Building2} label="Company Name" value={data.pe_company_name} />
              <Field icon={FileSignature} label="Product Name" value={data.pe_product_name} />
              <Field icon={Copyright} label="Copyright" value={data.pe_copyright} />
              <Field icon={FileSignature} label="Original Filename" value={data.pe_original_filename} />
              <Field icon={FileSignature} label="File Description" value={data.pe_file_description} />
              <Field icon={FileSignature} label="File Version" value={data.pe_file_version} />
            </div>
          )}

          {data.risk_factors.length > 0 && (
            <div>
              <div style={{ fontSize: 10.5, fontWeight: 700, letterSpacing: 0.6, color: 'var(--text-dim)', marginBottom: 8, textTransform: 'uppercase' }}>
                Risk Factors (local static analysis)
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {data.risk_factors.map((f, i) => (
                  <div key={i} style={{ display: 'flex', gap: 8, fontSize: 14.5, color: 'var(--text-mid)' }}>
                    <ShieldAlert size={13} color="var(--risk-medium)" style={{ flexShrink: 0, marginTop: 2 }} />
                    {f}
                  </div>
                ))}
              </div>
            </div>
          )}

          {!data.is_pe && (
            <div style={{ display: 'flex', gap: 8, fontSize: 14.5, color: 'var(--text-dim)' }}>
              <EyeOff size={13} style={{ flexShrink: 0, marginTop: 2 }} />
              Not a PE (.exe/.dll) file — signature and copyright metadata unavailable.
            </div>
          )}
        </div>

        <ScoreColumn>
          <ScoreBadge score={data.risk_score} label="Local Risk Score" size={144} stacked />
        </ScoreColumn>
      </div>
    </GlassCard>
    <SecurityChecksCard checks={data.security_checks} />
    </>
  );
}
