// Real AI chat assistant — calls the backend's /api/chat endpoint, which
// forwards to Google's Gemini API server-side (API key never touches the
// browser). Mirrors the same pattern as analysisService.ts.
import { apiClient } from "./client";

export async function sendChatMessage(message: string): Promise<string> {
  const res = await apiClient.post<{ reply: string }>("/api/chat", { message });
  return res.reply;
}

export async function resetChat(): Promise<void> {
  await apiClient.post("/api/chat/reset");
}