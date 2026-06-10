import type { ScanResult } from "./types";

// Calls go to THIS app's own origin under /api/*; next.config.ts proxies them
// (server-side) to the analyzer. Keeping the browser same-origin removes CORS and
// mixed-content entirely, so there is no analyzer URL in the client bundle.
export const API_URL = "";

export const MAX_UPLOAD_BYTES = 50 * 1024 * 1024;

export class ApiError extends Error {}

async function readError(res: Response): Promise<string> {
  try {
    const body = await res.json();
    if (body && typeof body.error === "string") return body.error;
  } catch {
    /* ignore */
  }
  return `Request failed (${res.status})`;
}

/** Uploads a JAR and returns its report. Caches it in sessionStorage for the report page. */
export async function scanFile(file: File): Promise<ScanResult> {
  const form = new FormData();
  form.append("file", file);

  let res: Response;
  try {
    res = await fetch(`${API_URL}/api/scan`, { method: "POST", body: form });
  } catch {
    throw new ApiError(
      "Could not reach the analyzer service — it may be starting up. Please try again in a moment.",
    );
  }
  if (!res.ok) {
    throw new ApiError(await readError(res));
  }
  const result = (await res.json()) as ScanResult;
  cacheReport(result);
  return result;
}

/** Fetches a stored report by id (falls back from the sessionStorage cache). */
export async function getReport(id: string): Promise<ScanResult> {
  const cached = readCachedReport(id);
  if (cached) return cached;

  const res = await fetch(`${API_URL}/api/scan/${encodeURIComponent(id)}`);
  if (!res.ok) {
    throw new ApiError(await readError(res));
  }
  return (await res.json()) as ScanResult;
}

export async function getDemo(): Promise<ScanResult> {
  const res = await fetch(`${API_URL}/api/demo`);
  if (!res.ok) {
    throw new ApiError(await readError(res));
  }
  return (await res.json()) as ScanResult;
}

function cacheReport(result: ScanResult) {
  if (typeof window === "undefined") return;
  try {
    sessionStorage.setItem(`pg:report:${result.id}`, JSON.stringify(result));
  } catch {
    /* storage full / unavailable — the report page will refetch */
  }
}

function readCachedReport(id: string): ScanResult | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = sessionStorage.getItem(`pg:report:${id}`);
    return raw ? (JSON.parse(raw) as ScanResult) : null;
  } catch {
    return null;
  }
}
