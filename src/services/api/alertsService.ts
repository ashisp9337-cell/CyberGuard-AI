// Alert channels (Telegram / email / WhatsApp) configured in backend/.env.
import { apiClient } from "./client";

export interface AlertChannelStatus {
  telegram: boolean;
  email: boolean;
  whatsapp: boolean;
  whatsappProvider: string;
  minScore: number;
  dedupMinutes: number;
}

export interface AlertSendResult {
  channel: string;
  status: "sent" | "failed" | "not_configured" | "disabled_by_user" | string;
  error: string;
  at: string;
}

export async function getAlertStatus(): Promise<AlertChannelStatus> {
  return apiClient.get<AlertChannelStatus>("/api/alerts/status");
}

export async function sendTestAlert(): Promise<{ channels: AlertChannelStatus; results: AlertSendResult[] }> {
  return apiClient.post<{ channels: AlertChannelStatus; results: AlertSendResult[] }>("/api/alerts/test", {});
}
