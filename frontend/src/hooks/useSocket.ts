import { useEffect, useRef, useState, useCallback } from "react";
import type { Alert, LiveStats } from "../types";
import { api } from "../api/client";

export function useSocket() {
  const [isConnected, setIsConnected] = useState(false);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [stats, setStats] = useState<LiveStats | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchStats = useCallback(async () => {
    try {
      const res = await api.getOverview() as { success: boolean; data: LiveStats };
      if (res.success && res.data) {
        setStats(res.data);
      }
      setIsConnected(true);
    } catch {
      setIsConnected(false);
    }
  }, []);

  const fetchAlerts = useCallback(async () => {
    try {
      const res = await api.getAlerts({ limit: 50 }) as { success: boolean; alerts: Alert[] };
      if (res.success && res.alerts) {
        setAlerts(res.alerts);
      }
    } catch {
      // Silently fail
    }
  }, []);

  useEffect(() => {
    // Initial fetch
    fetchStats();
    fetchAlerts();

    // Poll every 2 seconds for real-time updates
    pollRef.current = setInterval(() => {
      fetchStats();
      fetchAlerts();
    }, 2000);

    return () => {
      if (pollRef.current) {
        clearInterval(pollRef.current);
      }
    };
  }, [fetchStats, fetchAlerts]);

  return { isConnected, alerts, stats };
}
