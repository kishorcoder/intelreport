import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, Upload, History, Loader2, RefreshCw } from 'lucide-react';
import { lookupIp, lookupUrl, lookupHash, uploadFile } from '../lib/api';
import type { FileLookup, HashLookupResult, IPLookup, UrlLookup } from '../lib/types';
import { GlassCard } from '../components/GlassCard';
import { IpResultCard, UrlResultCard, FileResultCard } from '../components/ResultCard';

const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6_RE = /^[0-9a-fA-F:]+:[0-9a-fA-F:]+$/;
const SHA256_RE = /^[a-fA-F0-9]{64}$/;

type Result =
  | { kind: 'ip'; data: IPLookup }
  | { kind: 'url'; data: UrlLookup }
  | { kind: 'file'; data: FileLookup }
  | { kind: 'hash-not-found'; sha256: string; note: string };

function classify(input: string): 'ip' | 'hash' | 'url' {
  const trimmed = input.trim();
  if (IPV4_RE.test(trimmed) || IPV6_RE.test(trimmed)) return 'ip';
  if (SHA256_RE.test(trimmed)) return 'hash';
  return 'url';
}

const SHIELD_MASK =
  "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='1.5' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z'/%3E%3C/svg%3E\")";

const LAST_RESULT_KEY = 'intel:lastResult';

function loadLastResult(): Result | null {
  try {
    const raw = localStorage.getItem(LAST_RESULT_KEY);
    return raw ? (JSON.parse(raw) as Result) : null;
  } catch {
    return null;
  }
}

function saveLastResult(result: Result) {
  try {
    localStorage.setItem(LAST_RESULT_KEY, JSON.stringify(result));
  } catch {
    // private-browsing / quota errors — persistence is a nice-to-have, safe to skip
  }
}

export function Lookup() {
  const navigate = useNavigate();
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<Result | null>(loadLastResult);
  const fileInputRef = useRef<HTMLInputElement>(null);

  function applyResult(next: Result) {
    setResult(next);
    saveLastResult(next);
  }

  async function runLookup(value: string, forceRefresh = false) {
    const trimmed = value.trim();
    if (!trimmed) return;
    setLoading(true);
    setError(null);
    try {
      const kind = classify(trimmed);
      if (kind === 'ip') {
        const data = await lookupIp(trimmed, forceRefresh);
        applyResult({ kind: 'ip', data });
      } else if (kind === 'hash') {
        const res: HashLookupResult = await lookupHash(trimmed);
        if (res.found) {
          const { found, ...data } = res;
          applyResult({ kind: 'file', data: data as FileLookup });
        } else {
          applyResult({ kind: 'hash-not-found', sha256: res.sha256, note: res.note });
        }
      } else {
        const data = await lookupUrl(trimmed, forceRefresh);
        applyResult({ kind: 'url', data });
      }
    } catch {
      setError('Lookup failed — the backend may be unreachable, or an upstream source timed out.');
    } finally {
      setLoading(false);
    }
  }

  // On page reload there's already a cached result from localStorage — re-run
  // that same lookup so the shield loader shows (and the data gets revalidated
  // against the 24h cache) instead of the old snapshot just appearing instantly.
  useEffect(() => {
    if (result?.kind === 'ip') {
      setInput(result.data.ip);
      runLookup(result.data.ip);
    } else if (result?.kind === 'url') {
      setInput(result.data.url);
      runLookup(result.data.url);
    } else if (result?.kind === 'file') {
      setInput(result.data.sha256);
      runLookup(result.data.sha256);
    } else if (result?.kind === 'hash-not-found') {
      setInput(result.sha256);
      runLookup(result.sha256);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function handleFileUpload(file: File) {
    setLoading(true);
    setError(null);
    try {
      const data = await uploadFile(file);
      applyResult({ kind: 'file', data });
    } catch {
      setError('File upload/analysis failed.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={{ maxWidth: 900, margin: '0 auto' }}>
      <div
        style={{
          marginBottom: 24,
          maxWidth: 680,
          marginLeft: 'auto',
          marginRight: 'auto',
          background: 'rgba(30, 30, 34, 0.72)',
          backdropFilter: 'blur(40px) saturate(180%)',
          WebkitBackdropFilter: 'blur(40px) saturate(180%)',
          border: '1px solid rgba(255,255,255,0.1)',
          borderRadius: 16,
          boxShadow: '0 20px 50px -10px rgba(0,0,0,0.6), inset 0 1px 0 rgba(255,255,255,0.06)',
          padding: '4px 8px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <button
            onClick={() => runLookup(input)}
            disabled={loading}
            title="Lookup"
            style={{
              display: 'flex', alignItems: 'center', justifyContent: 'center', width: 40, height: 40, flexShrink: 0,
              borderRadius: 10, border: '1px solid rgba(255,255,255,0.1)', background: 'rgba(255,255,255,0.05)',
              color: 'var(--text-hi)', cursor: loading ? 'default' : 'pointer',
            }}
          >
            {loading ? <Loader2 size={17} className="spin" /> : <Search size={17} />}
          </button>
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && runLookup(input)}
            placeholder="Search an IP, domain, or SHA256 hash"
            style={{
              flex: 1, background: 'transparent', border: 'none',
              borderRadius: 12, padding: '11px 4px', fontSize: 16.5, outline: 'none',
              color: 'var(--text-hi)',
            }}
          />
          <button
            onClick={() => fileInputRef.current?.click()}
            disabled={loading}
            title="Upload File"
            style={{
              display: 'flex', alignItems: 'center', justifyContent: 'center', width: 40, height: 40, flexShrink: 0,
              borderRadius: 10, border: '1px solid rgba(255,255,255,0.1)', background: 'rgba(255,255,255,0.05)',
              color: 'var(--text-hi)', cursor: loading ? 'default' : 'pointer',
            }}
          >
            <Upload size={17} />
          </button>
          <input
            ref={fileInputRef}
            type="file"
            style={{ display: 'none' }}
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) handleFileUpload(f);
              e.target.value = '';
            }}
          />
          <button
            onClick={() => navigate('/history')}
            title="History"
            style={{
              display: 'flex', alignItems: 'center', justifyContent: 'center', width: 40, height: 40, flexShrink: 0,
              borderRadius: 10, border: '1px solid rgba(255,255,255,0.1)', background: 'rgba(255,255,255,0.05)',
              color: 'var(--text-hi)', cursor: 'pointer',
            }}
          >
            <History size={17} />
          </button>
        </div>
      </div>

      {loading && (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 14, minHeight: '50vh' }}>
          <div style={{ position: 'relative', width: 160, height: 160 }}>
            <div
              style={{
                position: 'absolute', inset: 0,
                background: 'rgba(255,255,255,0.1)',
                WebkitMaskImage: SHIELD_MASK,
                maskImage: SHIELD_MASK,
                WebkitMaskSize: 'contain',
                maskSize: 'contain',
                WebkitMaskRepeat: 'no-repeat',
                maskRepeat: 'no-repeat',
                WebkitMaskPosition: 'center',
                maskPosition: 'center',
              }}
            />
            <div
              className="shield-loader-fill"
              style={{
                position: 'absolute', inset: 0,
                WebkitMaskImage: SHIELD_MASK,
                maskImage: SHIELD_MASK,
                WebkitMaskSize: 'contain',
                maskSize: 'contain',
                WebkitMaskRepeat: 'no-repeat',
                maskRepeat: 'no-repeat',
                WebkitMaskPosition: 'center',
                maskPosition: 'center',
              }}
            />
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--text-dim)', fontSize: 13 }}>
            <Loader2 size={14} className="spin" /> Querying live sources...
          </div>
        </div>
      )}

      {error && (
        <GlassCard style={{ borderColor: 'rgba(238,27,36,0.4)', color: 'var(--risk-high)', fontSize: 13 }}>
          {error}
        </GlassCard>
      )}

      {!loading && (result?.kind === 'ip' || result?.kind === 'url') && (
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 10 }}>
          <button
            onClick={() => runLookup(result.kind === 'ip' ? result.data.ip : result.data.url, true)}
            title="Lookups are cached for 24h — this bypasses the cache and re-fetches from live sources"
            style={{
              display: 'flex', alignItems: 'center', gap: 6, background: 'none', border: 'none',
              color: 'var(--text-dim)', fontSize: 12, fontWeight: 600, cursor: 'pointer', padding: 0,
            }}
          >
            <RefreshCw size={12} />
            Re-check now
          </button>
        </div>
      )}

      {!loading && result?.kind === 'ip' && <IpResultCard data={result.data} />}
      {!loading && result?.kind === 'url' && <UrlResultCard data={result.data} />}
      {!loading && result?.kind === 'file' && <FileResultCard data={result.data} />}
      {!loading && result?.kind === 'hash-not-found' && (
        <GlassCard>
          <div style={{ fontSize: 13, color: 'var(--text-mid)', lineHeight: 1.6 }}>
            <strong style={{ color: 'var(--text-hi)' }}>No local record for this hash.</strong>
            <div style={{ marginTop: 8, fontFamily: 'var(--font-mono)', fontSize: 12, wordBreak: 'break-all' }}>{result.sha256}</div>
            <div style={{ marginTop: 10 }}>{result.note}</div>
          </div>
        </GlassCard>
      )}

      <style>{`
        .spin { animation: spin 0.8s linear infinite; }
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
      `}</style>
    </div>
  );
}
