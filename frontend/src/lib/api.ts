import type { FileLookup, HashLookupResult, HistoryItem, IPLookup, UrlLookup } from './types';

// Vite env var so the same build works locally and in production — set
// VITE_API_BASE=https://api.yourdomain.com in a .env.production file (or the
// host's environment-variable UI) before running `npm run build` for deploy.
const BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8200';

export type ApiErrorKind = 'offline' | 'rate-limit' | 'server';

/** Why a request failed, so the UI can say something more useful than "failed". */
export class ApiError extends Error {
  kind: ApiErrorKind;

  constructor(kind: ApiErrorKind, message: string) {
    super(message);
    this.kind = kind;
  }
}

export function describeError(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.kind === 'offline') return "Can't reach the lookup server right now — it may be offline. Please try again in a minute.";
    if (e.kind === 'rate-limit') return 'Too many lookups in a short time. Please wait a minute and try again.';
  }
  return 'The lookup server hit an error. Please try again.';
}

// 502/503/504 and Cloudflare's 52x/530 mean the server behind the tunnel didn't
// answer (asleep, restarting, or briefly offline), not that the request was bad.
const UNREACHABLE = new Set([502, 503, 504, 520, 521, 522, 523, 524, 530]);
const RETRY_DELAY_MS = 1500;

async function request(path: string, init?: RequestInit): Promise<Response> {
  let lastError: ApiError | null = null;
  for (let attempt = 0; attempt < 2; attempt++) {
    if (attempt) await new Promise((r) => setTimeout(r, RETRY_DELAY_MS));
    let res: Response;
    try {
      res = await fetch(`${BASE}${path}`, init);
    } catch {
      lastError = new ApiError('offline', 'Network request failed');
      continue; // one retry covers a short drop in the phone's connection
    }
    if (res.ok) return res;
    if (res.status === 429) throw new ApiError('rate-limit', 'Rate limited');
    if (UNREACHABLE.has(res.status)) {
      lastError = new ApiError('offline', `Server unreachable (${res.status})`);
      continue;
    }
    throw new ApiError('server', `Request failed: ${res.status}`);
  }
  throw lastError ?? new ApiError('offline', 'Server unreachable');
}

async function get<T>(path: string): Promise<T> {
  return (await request(path)).json();
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await request(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
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
  const res = await request('/api/files/upload', { method: 'POST', body: form });
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
