import type { FileLookup, HashLookupResult, HistoryItem, IPLookup, UrlLookup } from './types';

// Vite env var so the same build works locally and in production — set
// VITE_API_BASE=https://api.yourdomain.com in a .env.production file (or the
// host's environment-variable UI) before running `npm run build` for deploy.
const BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8200';

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`);
  if (!res.ok) throw new Error(`Request failed: ${res.status}`);
  return res.json();
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`Request failed: ${res.status}`);
  return res.json();
}

export function lookupIp(ip: string, refresh = false) {
  return get<IPLookup>(`/api/ip/${encodeURIComponent(ip)}${refresh ? '?refresh=true' : ''}`);
}

export function lookupUrl(url: string, refresh = false) {
  return post<UrlLookup>('/api/url/', { url, refresh });
}

export function lookupHash(sha256: string) {
  return get<HashLookupResult>(`/api/files/hash/${encodeURIComponent(sha256)}`);
}

export async function uploadFile(file: File) {
  const form = new FormData();
  form.append('file', file);
  const res = await fetch(`${BASE}/api/files/upload`, { method: 'POST', body: form });
  if (!res.ok) throw new Error(`Request failed: ${res.status}`);
  return res.json() as Promise<FileLookup>;
}

// Resolves either way: the opening screen only waits on this, it never blocks the app
// if the backend is down (lookups then show their own error).
export async function pingBackend(timeoutMs = 8000): Promise<boolean> {
  try {
    const res = await fetch(`${BASE}/api/health`, { signal: AbortSignal.timeout(timeoutMs) });
    return res.ok;
  } catch {
    return false;
  }
}

export function fetchHistory(limit = 30) {
  return get<HistoryItem[]>(`/api/history?limit=${limit}`);
}
