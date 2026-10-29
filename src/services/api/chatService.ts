// Real AI chat assistant — calls the backend's /api/chat endpoints, which
// forward to Google's Gemini API server-side (API key never touches the
// browser). Mirrors the same pattern as analysisService.ts.
//
// 21 Oct: streamed replies (Server-Sent Events), saved history, screenshot upload and actions that run only
// after the user presses Confirm.
import { apiClient, ApiError } from "./client";
import { API_CONFIG } from "./config";

export type ChatLanguage = "en" | "hi" | "or";

/** Something Threatora prepared (release an e-mail, allowlist an indicator, make a report). Runs only on Confirm. */
export interface ChatAction {
  id: string;
  kind: string;
  summary: string;
  status: string;
}

export interface ChatReply {
  reply: string;
  actions: ChatAction[];
}

export interface ChatHistoryItem {
  id: string;
  role: "user" | "assistant";
  text: string;
  createdAt: string | null;
  actions?: ChatAction[];
  attachment?: string;
}

export interface ScreenshotReply extends ChatReply {
  ocr: "ok" | "not_installed" | "failed";
  textFound: boolean;
  qrFound: number;
}

export async function sendChatMessage(message: string, language: ChatLanguage = "en"): Promise<ChatReply> {
  const res = await apiClient.post<{ reply: string; actions?: ChatAction[] }>("/api/chat", { message, language },
    { timeoutMs: 90000 });
  return { reply: res.reply, actions: res.actions ?? [] };
}

/** Streams the reply: onDelta gets each new piece of text as Threatora writes it. Resolves with the full reply. */
export async function streamChatMessage(
  message: string,
  language: ChatLanguage,
  onDelta: (text: string) => void,
): Promise<ChatReply> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 90000);
  let res: Response;
  try {
    res = await fetch(`${API_CONFIG.baseUrl}/api/chat/stream`, {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message, language }),
      signal: controller.signal,
    });
  } catch (e) {
    clearTimeout(timeout);
    if ((e as Error).name === "AbortError") {
      throw new ApiError(0, "TIMEOUT", "Threatora took too long to answer. Please try again.");
    }
    throw new ApiError(0, "NETWORK_ERROR", "Could not reach the CyberGuard backend. Is it running?");
  }
  if (!res.ok || !res.body) {
    clearTimeout(timeout);
    let msg = res.statusText || "Request failed";
    let code = "UNKNOWN_ERROR";
    try {
      const body = await res.json();
      msg = body?.error?.message ?? msg;
      code = body?.error?.code ?? code;
    } catch {
      // not JSON
    }
    throw new ApiError(res.status, code, msg);
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let done: ChatReply | null = null;
  try {
    for (;;) {
      const { value, done: finished } = await reader.read();
      if (finished) break;
      buffer += decoder.decode(value, { stream: true });
      let sep = buffer.indexOf("\n\n");
      while (sep !== -1) {
        const block = buffer.slice(0, sep);
        buffer = buffer.slice(sep + 2);
        sep = buffer.indexOf("\n\n");
        const line = block.split("\n").find((l) => l.startsWith("data: "));
        if (!line) continue;
        let ev: { type: string; text?: string; reply?: string; actions?: ChatAction[]; message?: string };
        try {
          ev = JSON.parse(line.slice(6));
        } catch {
          continue;
        }
        if (ev.type === "delta" && ev.text) onDelta(ev.text);
        else if (ev.type === "done") done = { reply: ev.reply ?? "", actions: ev.actions ?? [] };
        else if (ev.type === "error") throw new ApiError(500, "CHAT_ERROR", ev.message ?? "Threatora hit an error.");
      }
    }
  } catch (e) {
    if (e instanceof ApiError) throw e;
    if ((e as Error).name === "AbortError") {
      throw new ApiError(0, "TIMEOUT", "Threatora took too long to answer. Please try again.");
    }
    throw new ApiError(0, "NETWORK_ERROR", "The connection to CyberGuard was interrupted.");
  } finally {
    clearTimeout(timeout);
  }
  if (!done) throw new ApiError(0, "NETWORK_ERROR", "The connection to CyberGuard was interrupted.");
  return done;
}

/** A screenshot is read on the CyberGuard computer (QR + text); only the text read from it reaches the AI. */
export async function sendChatScreenshot(file: File, message: string, language: ChatLanguage): Promise<ScreenshotReply> {
  const form = new FormData();
  form.append("file", file);
  form.append("message", message);
  form.append("language", language);
  const res = await apiClient.post<ScreenshotReply>("/api/chat/image", form, { timeoutMs: 120000 });
  return { ...res, actions: res.actions ?? [] };
}

export async function loadChatHistory(limit = 50): Promise<ChatHistoryItem[]> {
  return apiClient.get<ChatHistoryItem[]>(`/api/chat/history?limit=${limit}`);
}

export async function confirmChatAction(id: string): Promise<{ message: string; status: string }> {
  return apiClient.post(`/api/chat/actions/${encodeURIComponent(id)}/confirm`, undefined, { timeoutMs: 60000 });
}

export async function cancelChatAction(id: string): Promise<{ message: string; status: string }> {
  return apiClient.post(`/api/chat/actions/${encodeURIComponent(id)}/cancel`);
}

export async function resetChat(): Promise<void> {
  await apiClient.post("/api/chat/reset");
}
