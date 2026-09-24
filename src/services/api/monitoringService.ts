// Real-time live monitoring via the backend's SSE stream
// (GET /api/monitoring/stream), which pushes actual ThreatEvent rows as
// they're created — not a client-side random generator.
import type { LiveEvent } from "@/types";
import { API_CONFIG } from "./config";

export function subscribeLiveEvents(onEvent: (event: LiveEvent) => void): () => void {
  const source = new EventSource(`${API_CONFIG.baseUrl}/api/monitoring/stream`, { withCredentials: true });

  source.addEventListener("threat_event", (e: MessageEvent) => {
    try {
      const data = JSON.parse(e.data);
      onEvent({
        id: data.id, severity: data.severity, title: data.title,
        description: data.description ?? "", target: data.target ?? "",
        riskScore: data.riskScore ?? 0, status: data.status ?? "active",
        timestamp: data.timestamp, category: data.category ?? "system",
      });
    } catch {
      // ignore malformed event
    }
  });

  return () => source.close();
}
