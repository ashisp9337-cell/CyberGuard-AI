// Real unread-notification count, backed by ThreatEvent rows with
// status="active" (see backend/app/api/routes/events.py).
import { apiClient } from "./client";

export async function getUnreadCount(): Promise<number> {
  const res = await apiClient.get<{ count: number }>("/api/events/unread-count");
  return res.count;
}

export async function markAllRead(): Promise<number> {
  const res = await apiClient.post<{ markedRead: number }>("/api/events/mark-all-read");
  return res.markedRead;
}