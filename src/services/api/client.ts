// ---------------------------------------------------------------------------
// Centralized API client. Every real backend call in the app should go
// through this — never scatter raw fetch() calls through components.
//
// Uses HTTP-only cookies for auth (credentials: "include"), so no token
// handling is needed here; the browser attaches the session cookie
// automatically to same-site requests.
// ---------------------------------------------------------------------------
import { API_CONFIG } from "./config";

export class ApiError extends Error {
  code: string;
  status: number;
  details?: unknown;

  constructor(status: number, code: string, message: string, details?: unknown) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

async function parseError(res: Response): Promise<ApiError> {
  try {
    const body = await res.json();
    const err = body?.error;
    return new ApiError(res.status, err?.code ?? "UNKNOWN_ERROR", err?.message ?? res.statusText, err?.details);
  } catch {
    return new ApiError(res.status, "UNKNOWN_ERROR", res.statusText || "Request failed");
  }
}

interface RequestOptions {
  timeoutMs?: number;
}

async function request<T>(path: string, init: RequestInit, options: RequestOptions = {}): Promise<T> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs ?? 30000);

  let res: Response;
  try {
    res = await fetch(`${API_CONFIG.baseUrl}${path}`, {
      ...init,
      credentials: "include",
      signal: controller.signal,
      headers: { ...(init.headers ?? {}) },
    });
  } catch (e) {
    clearTimeout(timeout);
    if ((e as Error).name === "AbortError") {
      throw new ApiError(0, "TIMEOUT", "The request timed out. Check your connection and try again.");
    }
    throw new ApiError(0, "NETWORK_ERROR", "Could not reach the CyberGuard backend. Is it running?");
  }
  clearTimeout(timeout);

  if (!res.ok) throw await parseError(res);
  if (res.status === 204) return undefined as T;
  const contentType = res.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) return (await res.json()) as T;
  return (await res.blob()) as unknown as T;
}

export const apiClient = {
  get<T>(path: string, options?: RequestOptions): Promise<T> {
    return request<T>(path, { method: "GET" }, options);
  },
  post<T>(path: string, body?: unknown, options?: RequestOptions): Promise<T> {
    const isForm = typeof FormData !== "undefined" && body instanceof FormData;
    return request<T>(path, {
      method: "POST",
      headers: isForm ? undefined : { "Content-Type": "application/json" },
      body: isForm ? (body as FormData) : body !== undefined ? JSON.stringify(body) : undefined,
    }, options);
  },
  put<T>(path: string, body?: unknown, options?: RequestOptions): Promise<T> {
    return request<T>(path, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    }, options);
  },
  patch<T>(path: string, body?: unknown, options?: RequestOptions): Promise<T> {
    return request<T>(path, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    }, options);
  },
  delete<T>(path: string, options?: RequestOptions): Promise<T> {
    return request<T>(path, { method: "DELETE" }, options);
  },
};
