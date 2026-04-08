import { useEffect, useRef, useState } from "react";
import { io, Socket } from "socket.io-client";
import type { Alert, LiveStats } from "../types";

export function useSocket() {
  const socketRef = useRef<Socket | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [stats, setStats] = useState<LiveStats | null>(null);

  useEffect(() => {
    const socket = io("/", {
      transports: ["websocket", "polling"],
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
    });

    socketRef.current = socket;

    socket.on("connect", () => setIsConnected(true));
    socket.on("disconnect", () => setIsConnected(false));

    socket.on("alert", (data: Alert) => {
      setAlerts((prev) => [data, ...prev].slice(0, 200));
    });

    socket.on("stats", (data: LiveStats) => {
      setStats(data);
    });

    socket.emit("subscribe", { channel: "alerts" });
    socket.emit("subscribe", { channel: "stats" });

    return () => {
      socket.disconnect();
    };
  }, []);

  return { isConnected, alerts, stats };
}
