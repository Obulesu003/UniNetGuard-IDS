import { useEffect, useRef, useState } from "react";
import { io, Socket } from "socket.io-client";
import type { Alert, LiveStats } from "../types";

const SOCKET_URL = "http://localhost:8000";

export function useSocket() {
  const socketRef = useRef<Socket | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [stats, setStats] = useState<LiveStats | null>(null);

  useEffect(() => {
    const socket = io(SOCKET_URL, {
      transports: ["websocket", "polling"],
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
      reconnection: true,
    });

    socketRef.current = socket;

    socket.on("connect", () => {
      setIsConnected(true);
      // Re-subscribe after connecting
      socket.emit("subscribe", { channel: "alerts" });
      socket.emit("subscribe", { channel: "stats" });
    });

    socket.on("disconnect", () => setIsConnected(false));

    socket.on("connect_error", (error: Error) => {
      console.error("Socket connection error:", error.message);
    });

    socket.on("alert", (data: Alert) => {
      setAlerts((prev) => [data, ...prev].slice(0, 200));
    });

    socket.on("stats", (data: LiveStats) => {
      setStats(data);
    });

    return () => {
      socket.disconnect();
    };
  }, []);

  return { isConnected, alerts, stats };
}
