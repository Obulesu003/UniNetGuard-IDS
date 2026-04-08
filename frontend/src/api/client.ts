const BASE = "/api";

async function request<T>(path: string, opts?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, opts);
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export const api = {
  // Alerts
  getAlerts: (params?: Record<string, string | number | boolean>) => {
    const qs = params
      ? "?" + new URLSearchParams(params as Record<string, string>).toString()
      : "";
    return request<{ success: boolean; total: number; alerts: any[] }>(
      `/alerts${qs}`
    );
  },
  resolveAlert: (id: string, resolved_by = "system") =>
    request(`/alerts/${id}/resolve?resolved_by=${resolved_by}`, { method: "POST" }),
  bulkResolve: (ids: string[], resolved_by = "system") =>
    request(`/alerts/bulk-resolve`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ alert_ids: ids, resolved_by }),
    }),

  // Packets
  getPackets: (params?: Record<string, string | number | boolean>) => {
    const qs = params
      ? "?" + new URLSearchParams(params as Record<string, string>).toString()
      : "";
    return request<{ success: boolean; total: number; packets: any[] }>(
      `/packets${qs}`
    );
  },
  getPacket: (id: string) =>
    request<{ success: boolean; packet: any; hex_dump: string | null }>(
      `/packets/${id}`
    ),
  getPacketStats: () =>
    request<{ success: boolean; data: any }>(`/packets/stats/overview`),

  // Stats
  getOverview: () =>
    request<{ success: boolean; data: any }>("/stats/overview"),
  getThroughput: (minutes = 5) =>
    request<{ success: boolean; series: any[]; summary: any }>(
      `/stats/throughput?minutes=${minutes}`
    ),
  getSummary: () =>
    request<{ success: boolean; data: any }>("/stats/summary"),

  // Capture
  getCaptureStatus: () =>
    request<{ success: boolean; data: any }>("/capture/status"),
  startCapture: (params: { interface?: string; bpf_filter?: string; synthetic_pps?: number }) =>
    request("/capture/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(params),
    }),
  startAttackSim: (params: { interface?: string }) =>
    request("/capture/attack-sim", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(params),
    }),
  stopCapture: () =>
    request("/capture/stop", { method: "POST" }),
  getInterfaces: () =>
    request<{ success: boolean; interfaces: any[] }>("/capture/interfaces"),
};
