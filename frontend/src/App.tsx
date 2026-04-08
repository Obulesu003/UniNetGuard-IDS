import { useState, useEffect, useCallback } from "react";
import { useSocket } from "./hooks/useSocket";
import { api } from "./api/client";
import type { Alert, AlertSummary, ThroughputPoint, CapturedPacket, PacketStats } from "./types";
import {
  Shield, AlertTriangle, Activity, Network, XCircle,
  Wifi, Server, Package, Search, ChevronRight, ArrowLeft,
  Globe, MapPin, Layers, FileText, Zap, BarChart3, Lock,
} from "lucide-react";
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer,
} from "recharts";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e",
};

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
function formatTime(ts: string): string {
  const d = new Date(ts);
  return d.toLocaleTimeString();
}
function formatTimeFull(ts: string): string {
  return new Date(ts).toLocaleString();
}

function SeverityBadge({ severity }: { severity: string }) {
  const color = SEVERITY_COLORS[severity] ?? "#6b7280";
  return (
    <span className="px-2 py-0.5 rounded text-xs font-semibold uppercase"
      style={{ background: color + "22", color, border: `1px solid ${color}44` }}>
      {severity}
    </span>
  );
}

function StatCard({ title, value, icon: Icon, sub, color = "#3b82f6" }: {
  title: string; value: string | number; icon: any; sub?: string; color?: string;
}) {
  return (
    <div className="bg-slate-800 rounded-xl p-5 border border-slate-700">
      <div className="flex items-center justify-between mb-3">
        <span className="text-slate-400 text-sm font-medium">{title}</span>
        <Icon size={18} style={{ color }} />
      </div>
      <div className="text-3xl font-bold" style={{ color }}>{value}</div>
      {sub && <div className="text-slate-500 text-xs mt-1">{sub}</div>}
    </div>
  );
}

// ── NAV ─────────────────────────────────────────────────────

type Page = "dashboard" | "packets" | "packet_detail";

function NavBar({ page, setPage }: { page: Page; setPage: (p: Page) => void }) {
  const tabs = [
    { id: "dashboard" as Page, label: "Dashboard", icon: BarChart3 },
    { id: "packets" as Page, label: "Packet Analysis", icon: Package },
  ];
  return (
    <div className="flex items-center gap-1 bg-slate-800/50 rounded-xl p-1 mb-6 border border-slate-700">
      {tabs.map((tab) => (
        <button key={tab.id} onClick={() => setPage(tab.id)}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
            page === tab.id
              ? "bg-blue-600 text-white shadow"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-700"
          }`}>
          <tab.icon size={14} />
          {tab.label}
        </button>
      ))}
    </div>
  );
}

// ── DASHBOARD PAGE ────────────────────────────────────────────

function DashboardPage({
  alerts, captureStatus, summary, throughput,
  onStop, onAttackSim, onLiveCapture,
}: {
  alerts: Alert[]; captureStatus: any; summary: AlertSummary | null;
  throughput: ThroughputPoint[];
  onStop: () => void;
  onAttackSim: (iface: string) => void; onLiveCapture: (iface: string) => void;
}) {
  return (
    <>
      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <StatCard title="Packets/s" value={captureStatus?.packets_per_second ?? 0} icon={Activity} color="#3b82f6" />
        <StatCard title="Throughput" value={formatBytes(captureStatus?.bytes_per_second ?? 0) + "/s"} icon={Network} color="#a78bfa" />
        <StatCard title="Total Packets" value={(captureStatus?.total_packets ?? 0).toLocaleString()} icon={Server} color="#22c55e" />
        <StatCard title="Total Alerts" value={summary?.by_severity ? Object.values(summary.by_severity).reduce((a, b) => a + b, 0) : 0} icon={AlertTriangle} color="#f97316" />
      </div>

      {/* Capture Control */}
      <CaptureControl status={captureStatus} onStop={onStop} onAttackSim={onAttackSim} onLiveCapture={onLiveCapture} />

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6">
        <div className="lg:col-span-2"><ThroughputChart data={throughput} /></div>
        <div className="space-y-4">
          <AlertSummaryPanel summary={summary} />
        </div>
      </div>

      {/* Alert Table */}
      <AlertTable alerts={alerts} />
    </>
  );
}

// ── PACKET ANALYSIS PAGE ────────────────────────────────────

function PacketAnalysisPage({ onSelect }: { onSelect: (id: string) => void }) {
  const [packets, setPackets] = useState<CapturedPacket[]>([]);
  const [total, setTotal] = useState(0);
  const [stats, setStats] = useState<PacketStats | null>(null);
  const [filter, setFilter] = useState("");
  const [protocol, setProtocol] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 3000);
    return () => clearInterval(interval);
  }, [protocol]);

  async function loadData() {
    try {
      const [pktRes, statsRes] = await Promise.all([
        api.getPackets(protocol ? { protocol, limit: 100 } : { limit: 100 }),
        api.getPacketStats(),
      ]);
      setPackets(pktRes.packets || []);
      setTotal(pktRes.total || 0);
      setStats(statsRes.data || null);
    } catch {}
    setLoading(false);
  }

  const filtered = filter
    ? packets.filter(p =>
        p.src_ip.includes(filter) || p.dst_ip.includes(filter) ||
        p.protocol.toLowerCase().includes(filter.toLowerCase()) ||
        String(p.src_port).includes(filter) ||
        String(p.dst_port).includes(filter)
      )
    : packets;

  return (
    <div className="space-y-4">
      {/* Stats Overview */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard title="Total Captured" value={stats.total_packets.toLocaleString()} icon={Package} color="#3b82f6" />
          <StatCard title="TCP" value={(stats.by_protocol["TCP"] || 0).toLocaleString()} icon={Zap} color="#8b5cf6" />
          <StatCard title="UDP" value={(stats.by_protocol["UDP"] || 0).toLocaleString()} icon={Zap} color="#ec4899" />
          <StatCard title="ICMP" value={(stats.by_protocol["ICMP"] || 0).toLocaleString()} icon={Zap} color="#22c55e" />
        </div>
      )}

      {/* Top IPs / Ports */}
      {stats && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="bg-slate-800 rounded-xl p-5 border border-slate-700">
            <h3 className="text-slate-300 font-semibold mb-3 flex items-center gap-2">
              <MapPin size={14} className="text-red-400" /> Top Sources
            </h3>
            {stats.top_sources.slice(0, 5).map((s, i) => (
              <div key={i} className="flex justify-between text-sm py-1 border-b border-slate-700/50 last:border-0">
                <span className="text-slate-400 font-mono text-xs">{s.ip}</span>
                <span className="text-slate-300">{s.count.toLocaleString()}</span>
              </div>
            ))}
          </div>
          <div className="bg-slate-800 rounded-xl p-5 border border-slate-700">
            <h3 className="text-slate-300 font-semibold mb-3 flex items-center gap-2">
              <Globe size={14} className="text-blue-400" /> Top Destinations
            </h3>
            {stats.top_destinations.slice(0, 5).map((s, i) => (
              <div key={i} className="flex justify-between text-sm py-1 border-b border-slate-700/50 last:border-0">
                <span className="text-slate-400 font-mono text-xs">{s.ip}</span>
                <span className="text-slate-300">{s.count.toLocaleString()}</span>
              </div>
            ))}
          </div>
          <div className="bg-slate-800 rounded-xl p-5 border border-slate-700">
            <h3 className="text-slate-300 font-semibold mb-3 flex items-center gap-2">
              <Lock size={14} className="text-green-400" /> Top Ports
            </h3>
            {stats.top_ports.slice(0, 5).map((s, i) => (
              <div key={i} className="flex justify-between text-sm py-1 border-b border-slate-700/50 last:border-0">
                <span className="text-slate-400 font-mono text-xs">:{s.port}</span>
                <span className="text-slate-300">{s.count.toLocaleString()}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input value={filter} onChange={e => setFilter(e.target.value)}
            placeholder="Filter by IP, port, or protocol..."
            className="w-full bg-slate-800 border border-slate-700 text-slate-200 rounded-lg pl-9 pr-4 py-2.5 text-sm focus:outline-none focus:border-blue-500 placeholder-slate-600" />
        </div>
        <select value={protocol} onChange={e => setProtocol(e.target.value)}
          className="bg-slate-800 border border-slate-700 text-slate-200 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:border-blue-500">
          <option value="">All Protocols</option>
          <option value="TCP">TCP</option>
          <option value="UDP">UDP</option>
          <option value="ICMP">ICMP</option>
          <option value="other">Other</option>
        </select>
        <button onClick={loadData} className="px-4 py-2.5 bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-lg text-sm transition">
          Refresh
        </button>
      </div>

      {/* Packet Table */}
      <div className="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden">
        <div className="flex items-center justify-between p-4 border-b border-slate-700">
          <h3 className="text-slate-300 font-semibold flex items-center gap-2">
            <Package size={16} className="text-blue-400" />
            Captured Packets ({total.toLocaleString()})
          </h3>
        </div>
        {loading ? (
          <div className="p-12 text-center text-slate-500">Loading packets...</div>
        ) : filtered.length === 0 ? (
          <div className="p-12 text-center text-slate-500">
            <Package size={40} className="mx-auto mb-3 opacity-30" />
            <p>No packets captured yet. Start capture to see traffic.</p>
          </div>
        ) : (
          <div className="overflow-x-auto max-h-[500px] overflow-y-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-slate-800">
                <tr className="text-slate-500 text-left text-xs">
                  <th className="px-4 py-2 font-medium">Time</th>
                  <th className="px-4 py-2 font-medium">Proto</th>
                  <th className="px-4 py-2 font-medium">Source</th>
                  <th className="px-4 py-2 font-medium">Destination</th>
                  <th className="px-4 py-2 font-medium">Port</th>
                  <th className="px-4 py-2 font-medium">Flags</th>
                  <th className="px-4 py-2 font-medium">Length</th>
                  <th className="px-4 py-2 font-medium">TTL</th>
                  <th className="px-4 py-2 font-medium">Info</th>
                  <th className="px-4 py-2 font-medium"></th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((pkt) => (
                  <tr key={pkt.id}
                    className={`border-t border-slate-700/50 hover:bg-slate-700/30 transition cursor-pointer ${
                      pkt.is_alert ? "bg-red-900/10" : ""
                    }`}>
                    <td className="px-4 py-2 text-slate-400 font-mono text-xs whitespace-nowrap">
                      {formatTime(pkt.timestamp)}
                    </td>
                    <td className="px-4 py-2">
                      <span className={`text-xs px-2 py-0.5 rounded font-semibold ${
                        pkt.protocol === "TCP" ? "bg-blue-500/20 text-blue-400" :
                        pkt.protocol === "UDP" ? "bg-purple-500/20 text-purple-400" :
                        pkt.protocol === "ICMP" ? "bg-green-500/20 text-green-400" :
                        "bg-slate-500/20 text-slate-400"
                      }`}>{pkt.protocol}</span>
                    </td>
                    <td className="px-4 py-2 text-slate-300 font-mono text-xs">{pkt.src_ip}</td>
                    <td className="px-4 py-2 text-slate-300 font-mono text-xs">{pkt.dst_ip}</td>
                    <td className="px-4 py-2 text-slate-400 font-mono text-xs">{pkt.dst_port > 0 ? pkt.dst_port : "—"}</td>
                    <td className="px-4 py-2">
                      {pkt.tcp_flags ? (
                        <span className="text-xs font-mono text-amber-400">{pkt.tcp_flags}</span>
                      ) : (
                        <span className="text-slate-600">—</span>
                      )}
                    </td>
                    <td className="px-4 py-2 text-slate-400 font-mono text-xs">{pkt.length}</td>
                    <td className="px-4 py-2 text-slate-500 font-mono text-xs">{pkt.ttl}</td>
                    <td className="px-4 py-2 text-slate-400 text-xs max-w-[200px] truncate">
                      {pkt.dns_query || pkt.http_method || pkt.payload_preview?.slice(0, 30) || "—"}
                    </td>
                    <td className="px-4 py-2">
                      {pkt.is_alert && (
                        <span className="text-xs bg-red-500/20 text-red-400 px-2 py-0.5 rounded flex items-center gap-1">
                          <AlertTriangle size={10} /> Alert
                        </span>
                      )}
                      <button onClick={() => onSelect(pkt.id)}
                        className="text-slate-500 hover:text-blue-400 transition ml-2">
                        <ChevronRight size={14} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

// ── PACKET DETAIL PAGE ──────────────────────────────────────

function PacketDetailPage({ packetId, onBack }: { packetId: string; onBack: () => void }) {
  const [packet, setPacket] = useState<CapturedPacket | null>(null);
  const [hexDump, setHexDump] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getPacket(packetId).then(r => {
      setPacket(r.packet);
      setHexDump(r.hex_dump);
    }).catch(() => {}).finally(() => setLoading(false));
  }, [packetId]);

  if (loading) return <div className="text-center text-slate-500 py-20">Loading packet details...</div>;
  if (!packet) return <div className="text-center text-slate-500 py-20">Packet not found</div>;

  return (
    <div className="space-y-4">
      <button onClick={onBack}
        className="flex items-center gap-2 text-slate-400 hover:text-slate-200 transition text-sm">
        <ArrowLeft size={14} /> Back to Packets
      </button>

      {/* Header */}
      <div className="bg-slate-800 rounded-xl p-6 border border-slate-700">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${
              packet.protocol === "TCP" ? "bg-blue-600/20" :
              packet.protocol === "UDP" ? "bg-purple-600/20" :
              "bg-green-600/20"
            }`}>
              <Layers size={24} className={
                packet.protocol === "TCP" ? "text-blue-400" :
                packet.protocol === "UDP" ? "text-purple-400" : "text-green-400"
              } />
            </div>
            <div>
              <h2 className="text-xl font-bold text-white">{packet.protocol} Packet</h2>
              <p className="text-slate-500 text-sm">{packet.length} bytes · {formatTimeFull(packet.timestamp)}</p>
            </div>
          </div>
          {packet.is_alert && (
            <span className="px-3 py-1.5 bg-red-500/20 text-red-400 rounded-lg text-sm font-semibold border border-red-500/30">
              <AlertTriangle size={12} className="inline mr-1" /> Triggered Alert
            </span>
          )}
        </div>

        {/* IP Headers */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: "Source IP", value: packet.src_ip, sub: `Port ${packet.src_port}` },
            { label: "Destination IP", value: packet.dst_ip, sub: `Port ${packet.dst_port}` },
            { label: "TTL", value: packet.ttl, sub: "Time to Live" },
            { label: "IP Length", value: packet.ip_length || packet.length, sub: "bytes" },
          ].map(({ label, value, sub }) => (
            <div key={label} className="bg-slate-700/50 rounded-lg p-3">
              <div className="text-slate-500 text-xs mb-1">{label}</div>
              <div className="text-slate-200 font-mono font-semibold">{value}</div>
              <div className="text-slate-500 text-xs">{sub}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Protocol Layers */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Network Layer */}
        <div className="bg-slate-800 rounded-xl p-5 border border-slate-700">
          <h3 className="text-slate-300 font-semibold mb-4 flex items-center gap-2">
            <Globe size={14} className="text-blue-400" /> Network Layer (IP)
          </h3>
          <div className="space-y-2">
            {[
              ["Version", "4"],
              ["Header Length", `${packet.ip_length > 20 ? packet.ip_length : 20} bytes`],
              ["TTL", `${packet.ttl}`],
              ["Protocol", packet.protocol],
              ["Checksum", packet.checksum ? `0x${packet.checksum.toString(16).toUpperCase().padStart(4, "0")}` : "N/A"],
            ].map(([k, v]) => (
              <div key={k} className="flex justify-between text-sm py-1 border-b border-slate-700/50 last:border-0">
                <span className="text-slate-500">{k}</span>
                <span className="text-slate-300 font-mono">{v}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Transport Layer */}
        <div className="bg-slate-800 rounded-xl p-5 border border-slate-700">
          <h3 className="text-slate-300 font-semibold mb-4 flex items-center gap-2">
            <Layers size={14} className="text-purple-400" /> Transport Layer ({packet.protocol})
          </h3>
          <div className="space-y-2">
            {packet.protocol === "TCP" ? (
              <>
                {[
                  ["Source Port", packet.src_port],
                  ["Destination Port", packet.dst_port],
                  ["Sequence Number", packet.tcp_seq],
                  ["Ack Number", packet.tcp_ack],
                  ["Window Size", packet.window_size],
                  ["Flags", packet.tcp_flags || "None"],
                  ["TCP Header Length", "20+ bytes"],
                ].map(([k, v]) => (
                  <div key={k} className="flex justify-between text-sm py-1 border-b border-slate-700/50 last:border-0">
                    <span className="text-slate-500">{k}</span>
                    <span className="text-slate-300 font-mono">{v}</span>
                  </div>
                ))}
                {/* TCP Flag Breakdown */}
                <div className="mt-3 pt-3 border-t border-slate-700">
                  <div className="text-slate-500 text-xs mb-2">Flag Bits</div>
                  <div className="flex gap-2 flex-wrap">
                    {[
                      { flag: "S", label: "SYN", color: "#3b82f6" },
                      { flag: "A", label: "ACK", color: "#22c55e" },
                      { flag: "F", label: "FIN", color: "#f97316" },
                      { flag: "R", label: "RST", color: "#ef4444" },
                      { flag: "P", label: "PSH", color: "#a78bfa" },
                      { flag: "U", label: "URG", color: "#eab308" },
                    ].map(({ flag, label, color }) => {
                      const active = packet.tcp_flags?.includes(flag);
                      return (
                        <span key={flag}
                          className={`text-xs px-2 py-1 rounded font-mono ${
                            active ? "text-white" : "text-slate-600"
                          }`}
                          style={{ background: active ? color : "#1e293b" }}>
                          {label}
                        </span>
                      );
                    })}
                  </div>
                </div>
              </>
            ) : packet.protocol === "UDP" ? (
              <>
                {[
                  ["Source Port", packet.src_port],
                  ["Destination Port", packet.dst_port],
                  ["UDP Length", `${packet.length} bytes`],
                ].map(([k, v]) => (
                  <div key={k} className="flex justify-between text-sm py-1 border-b border-slate-700/50 last:border-0">
                    <span className="text-slate-500">{k}</span>
                    <span className="text-slate-300 font-mono">{v}</span>
                  </div>
                ))}
              </>
            ) : (
              <>
                {[
                  ["ICMP Type", packet.src_port],
                  ["ICMP Code", packet.dst_port],
                ].map(([k, v]) => (
                  <div key={k} className="flex justify-between text-sm py-1 border-b border-slate-700/50 last:border-0">
                    <span className="text-slate-500">{k}</span>
                    <span className="text-slate-300 font-mono">{v}</span>
                  </div>
                ))}
              </>
            )}
          </div>
        </div>
      </div>

      {/* Application Layer */}
      {(packet.dns_query || packet.http_method || packet.payload_preview) && (
        <div className="bg-slate-800 rounded-xl p-5 border border-slate-700">
          <h3 className="text-slate-300 font-semibold mb-4 flex items-center gap-2">
            <FileText size={14} className="text-green-400" /> Application Layer
          </h3>
          {packet.http_method && (
            <div className="mb-3">
              <span className="text-xs bg-green-500/20 text-green-400 px-2 py-1 rounded font-semibold">
                {packet.http_method}
              </span>
              {packet.payload_preview && (
                <code className="block mt-2 text-xs text-slate-400 bg-slate-700 rounded p-2 overflow-x-auto">
                  {packet.payload_preview}
                </code>
              )}
            </div>
          )}
          {packet.dns_query && (
            <div>
              <span className="text-xs text-slate-500 mb-1 block">DNS Query</span>
              <span className="text-slate-200 font-mono">{packet.dns_query}</span>
            </div>
          )}
          {packet.payload_preview && !packet.http_method && !packet.dns_query && (
            <div>
              <span className="text-xs text-slate-500 mb-1 block">Payload Preview</span>
              <code className="block text-xs text-slate-400 bg-slate-700 rounded p-2 overflow-x-auto">
                {packet.payload_preview}
              </code>
            </div>
          )}
        </div>
      )}

      {/* Hex Dump */}
      {hexDump && (
        <div className="bg-slate-800 rounded-xl p-5 border border-slate-700">
          <h3 className="text-slate-300 font-semibold mb-4 flex items-center gap-2">
            <FileText size={14} className="text-amber-400" /> Hex Dump (first 64 bytes)
          </h3>
          <div className="grid grid-cols-[auto_1fr] gap-x-4 font-mono text-xs">
            {/* Offset column */}
            <div className="text-slate-600 space-y-0.5">
              {[0, 16, 32, 48].map(o => (
                <div key={o} className="text-right pr-3">{o.toString(16).toUpperCase().padStart(4, "0")}</div>
              ))}
            </div>
            {/* Hex values */}
            <div className="text-slate-400 space-y-0.5">
              {Array.from({ length: 4 }, (_, row) => {
                const bytes = hexDump.slice(row * 32, (row + 1) * 32);
                const hexPairs = bytes.match(/.{1,2}/g) || [];
                return (
                  <div key={row} className="flex gap-1 flex-wrap">
                    {Array.from({ length: 16 }, (_, col) => {
                      const byte = hexPairs[col];
                      return (
                        <span key={col} className="w-[1.5ch] text-right">
                          <span className="text-amber-400">{byte || "  "}</span>
                          <span className="text-slate-600"> </span>
                          {col === 7 && <span className="mr-1"></span>}
                        </span>
                      );
                    })}
                    <span className="text-slate-600 ml-2">
                      {hexPairs.slice(0, 16).map((b) =>
                        b ? String.fromCharCode(parseInt(b, 16)).replace(/[^\x20-\x7E]/, ".") : " "
                      ).join("")}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* Raw Data */}
      {packet.payload_preview && (
        <div className="bg-slate-800 rounded-xl p-5 border border-slate-700">
          <h3 className="text-slate-300 font-semibold mb-3 flex items-center gap-2">
            <Zap size={14} className="text-cyan-400" /> Raw Payload
          </h3>
          <pre className="text-xs text-slate-400 bg-slate-700/50 rounded-lg p-4 overflow-x-auto whitespace-pre-wrap break-all font-mono">
            {packet.payload_preview}
          </pre>
        </div>
      )}
    </div>
  );
}

// ── SUPPORTING COMPONENTS ────────────────────────────────────

function ThroughputChart({ data }: { data: ThroughputPoint[] }) {
  return (
    <div className="bg-slate-800 rounded-xl p-5 border border-slate-700">
      <h3 className="text-slate-300 font-semibold mb-4 flex items-center gap-2">
        <Activity size={16} className="text-blue-400" /> Throughput
      </h3>
      <ResponsiveContainer width="100%" height={200}>
        <LineChart data={data.slice(-30)}>
          <XAxis dataKey="timestamp" stroke="#475569" fontSize={10} tickLine={false}
            tickFormatter={(v: string) => {
              const d = new Date(v);
              return `${d.getHours()}:${String(d.getMinutes()).padStart(2, "0")}`;
            }} />
          <YAxis stroke="#475569" fontSize={10} tickLine={false} axisLine={false} />
          <Tooltip contentStyle={{ background: "#1e293b", border: "1px solid #334155", borderRadius: 8 }}
            labelStyle={{ color: "#94a3b8" }} itemStyle={{ color: "#60a5fa" }} />
          <Line type="monotone" dataKey="packets_per_second" stroke="#3b82f6" dot={false} strokeWidth={2} name="Packets/s" />
          <Line type="monotone" dataKey="bytes_per_second" stroke="#a78bfa" dot={false} strokeWidth={2} name="Bytes/s" />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

function AlertSummaryPanel({ summary }: { summary: AlertSummary | null }) {
  if (!summary) return null;
  const severities = ["critical", "high", "medium", "low"];
  const total = Object.values(summary.by_severity).reduce((a, b) => a + b, 0);
  return (
    <div className="bg-slate-800 rounded-xl p-5 border border-slate-700">
      <h3 className="text-slate-300 font-semibold mb-4 flex items-center gap-2">
        <AlertTriangle size={16} className="text-amber-400" /> Alerts
      </h3>
      <div className="space-y-3">
        {severities.map(sev => {
          const count = summary.by_severity[sev] ?? 0;
          const color = SEVERITY_COLORS[sev];
          const pct = total > 0 ? (count / total) * 100 : 0;
          return (
            <div key={sev}>
              <div className="flex justify-between text-sm mb-1">
                <span className="capitalize" style={{ color }}>{sev}</span>
                <span className="text-slate-400">{count}</span>
              </div>
              <div className="h-1.5 bg-slate-700 rounded-full overflow-hidden">
                <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, background: color }} />
              </div>
            </div>
          );
        })}
      </div>
      {summary.by_category && Object.keys(summary.by_category).length > 0 && (
        <div className="mt-4 pt-4 border-t border-slate-700">
          <div className="text-xs text-slate-500 mb-2">Top Categories</div>
          {Object.entries(summary.by_category).sort((a, b) => b[1] - a[1]).slice(0, 4).map(([cat, cnt]) => (
            <div key={cat} className="flex justify-between text-xs mt-1">
              <span className="text-slate-400 capitalize">{cat.replace("_", " ")}</span>
              <span className="text-slate-300">{cnt}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function AlertTable({ alerts }: { alerts: Alert[] }) {
  return (
    <div className="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden">
      <div className="flex items-center justify-between p-4 border-b border-slate-700">
        <h3 className="text-slate-300 font-semibold flex items-center gap-2">
          <Shield size={16} className="text-blue-400" /> Alerts ({alerts.length})
        </h3>
      </div>
      {alerts.length === 0 ? (
        <div className="p-12 text-center text-slate-500">
          <Shield size={40} className="mx-auto mb-3 opacity-30" />
          <p>No alerts detected yet.</p>
        </div>
      ) : (
        <div className="overflow-x-auto max-h-96 overflow-y-auto">
          <table className="w-full text-sm">
            <thead className="sticky top-0 bg-slate-800">
              <tr className="text-slate-500 text-left text-xs">
                <th className="px-4 py-2 font-medium">Sev</th>
                <th className="px-4 py-2 font-medium">Time</th>
                <th className="px-4 py-2 font-medium">Title</th>
                <th className="px-4 py-2 font-medium">Source</th>
                <th className="px-4 py-2 font-medium">Proto</th>
                <th className="px-4 py-2 font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map(alert => (
                <tr key={alert.id} className="border-t border-slate-700/50 hover:bg-slate-700/30 transition">
                  <td className="px-4 py-2"><SeverityBadge severity={alert.severity} /></td>
                  <td className="px-4 py-2 text-slate-400 font-mono text-xs">{formatTime(alert.timestamp)}</td>
                  <td className="px-4 py-2 text-slate-200 max-w-xs truncate">{alert.title}</td>
                  <td className="px-4 py-2 text-slate-400 font-mono text-xs">{alert.source_ip}:{alert.source_port || "—"}</td>
                  <td className="px-4 py-2 text-slate-400">{alert.protocol}</td>
                  <td className="px-4 py-2">
                    <span className={`text-xs px-2 py-0.5 rounded font-medium ${
                      alert.resolved ? "bg-slate-600/50 text-slate-400" : "bg-green-500/20 text-green-400"
                    }`}>{alert.resolved ? "Resolved" : "Active"}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function CaptureControl({ status, onStop, onAttackSim, onLiveCapture }: {
  status: any;
  onStop: () => void;
  onAttackSim: (iface: string) => void;
  onLiveCapture: (iface: string) => void;
}) {
  const [selectedIface, setSelectedIface] = useState("Wi-Fi");

  const isRunning = status?.is_running;
  const mode = status?.mode;

  return (
    <div className="bg-slate-800 rounded-xl p-5 border border-slate-700">
      <h3 className="text-slate-300 font-semibold mb-4 flex items-center gap-2">
        <Server size={16} className="text-green-400" /> Capture Control
      </h3>
      <div className="flex items-center gap-3 flex-wrap">
        {/* Interface selector */}
        <select value={selectedIface} onChange={e => setSelectedIface(e.target.value)}
          className="bg-slate-700 border border-slate-600 text-slate-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-500">
          <option value="Wi-Fi">Wi-Fi</option>
          <option value="Ethernet">Ethernet</option>
          <option value="Loopback">Loopback</option>
        </select>

        {/* Attack Simulation — sends real packets, triggers real detection */}
        {!isRunning ? (
          <>
            <button onClick={() => onAttackSim(selectedIface)}
              className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-500 text-white rounded-lg text-sm transition font-medium">
              <Zap size={14} /> Attack Simulation
            </button>

            {/* Live Capture — passive, captures existing traffic */}
            <button onClick={() => onLiveCapture(selectedIface)}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm transition">
              <Wifi size={14} /> Live Capture
            </button>
          </>
        ) : (
          <button onClick={onStop}
            className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-500 text-white rounded-lg text-sm transition">
            <XCircle size={14} /> Stop
          </button>
        )}

        {/* Status indicator */}
        <div className="ml-auto flex items-center gap-2">
          <div className={`w-2.5 h-2.5 rounded-full ${isRunning ? "bg-green-400 animate-pulse" : "bg-slate-500"}`} />
          <span className="text-sm text-slate-400">
            {isRunning
              ? `${mode === "attack_sim" ? "Attack Sim" : mode === "synthetic" ? "Synthetic" : "Live"} · ${status.interface}`
              : "Stopped"}
          </span>
        </div>
      </div>

      {/* Mode description */}
      {!isRunning && (
        <div className="mt-3 text-xs text-slate-500 flex gap-6">
          <span><span className="text-red-400">● Attack Simulation</span> — sends real attack packets, triggers detection</span>
          <span><span className="text-blue-400">● Live Capture</span> — captures real network traffic</span>
        </div>
      )}
    </div>
  );
}

// ── MAIN APP ────────────────────────────────────────────────

export default function App() {
  const { isConnected, alerts: socketAlerts, stats: liveStats } = useSocket();
  const [page, setPage] = useState<Page>("dashboard");
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [summary, setSummary] = useState<AlertSummary | null>(null);
  const [throughput, setThroughput] = useState<ThroughputPoint[]>([]);
  const [captureStatus, setCaptureStatus] = useState<any>(null);
  const [selectedPacketId, setSelectedPacketId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        const [summaryRes, throughputRes, captureRes, alertsRes] = await Promise.all([
          api.getSummary(),
          api.getThroughput(5),
          api.getCaptureStatus(),
          api.getAlerts({ limit: 50 }),
        ]);
        if (summaryRes.success) setSummary(summaryRes.data);
        if (throughputRes.success) setThroughput(throughputRes.series);
        if (captureRes.success) setCaptureStatus(captureRes.data);
        if (alertsRes.success) setAlerts(alertsRes.alerts || []);
      } catch {}
      setLoading(false);
    }
    load();
    const interval = setInterval(load, 5000);
    return () => clearInterval(interval);
  }, []);

  // Sync socket alerts into React state (real-time)
  useEffect(() => {
    if (socketAlerts.length > 0) {
      setAlerts((prev: Alert[]) => {
        const existing = new Set(prev.map(a => a.id));
        const newAlerts = socketAlerts.filter(a => !existing.has(a.id));
        if (newAlerts.length === 0) return prev;
        return [...newAlerts, ...prev].slice(0, 200);
      });
    }
  }, [socketAlerts]);

  // Sync socket stats into capture status (real-time dashboard)
  useEffect(() => {
    if (liveStats) {
      setCaptureStatus((prev: Record<string, unknown>) => ({
        ...(prev || {}),
        packets_per_second: liveStats.packets_per_second,
        bytes_per_second: liveStats.bytes_per_second,
        total_packets: liveStats.total_packets,
        total_bytes: liveStats.total_bytes,
        active_alerts: liveStats.active_alerts,
      }));
    }
  }, [liveStats]);

  const handleStop = useCallback(async () => {
    await api.stopCapture();
    const res = await api.getCaptureStatus();
    if (res.success) setCaptureStatus(res.data);
    // Reload alerts after stopping
    const alertsRes = await api.getAlerts({ limit: 50 });
    if (alertsRes.success) setAlerts(alertsRes.alerts || []);
  }, []);

  const handleAttackSim = useCallback(async (iface: string) => {
    const res = await api.startAttackSim({ interface: iface }) as { success: boolean };
    if (res.success) {
      const captureRes = await api.getCaptureStatus();
      if (captureRes.success) setCaptureStatus(captureRes.data);
    }
  }, []);

  const handleLiveCapture = useCallback(async (iface: string) => {
    await api.startCapture({ interface: iface });
    const res = await api.getCaptureStatus();
    if (res.success) setCaptureStatus(res.data);
  }, []);

  if (loading) {
    return <div className="min-h-screen flex items-center justify-center text-slate-500">Loading UniNetGuard IDS...</div>;
  }

  return (
    <div className="min-h-screen p-6 max-w-screen-2xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-blue-600 rounded-xl flex items-center justify-center">
            <Shield size={22} className="text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">UniNetGuard IDS</h1>
            <p className="text-slate-500 text-xs">Intrusion Detection System</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <div className={`w-2 h-2 rounded-full ${isConnected ? "bg-green-400" : "bg-red-400"}`} />
          <span className="text-xs text-slate-400">{isConnected ? "Live" : "Disconnected"}</span>
        </div>
      </div>

      {/* Navigation */}
      <NavBar page={page} setPage={setPage} />

      {/* Pages */}
      {page === "dashboard" && (
        <DashboardPage
          alerts={alerts} captureStatus={captureStatus} summary={summary}
          throughput={throughput}
          onStop={handleStop}
          onAttackSim={handleAttackSim} onLiveCapture={handleLiveCapture}
        />
      )}
      {page === "packets" && (
        <PacketAnalysisPage onSelect={id => { setSelectedPacketId(id); setPage("packet_detail"); }} />
      )}
      {page === "packet_detail" && selectedPacketId && (
        <PacketDetailPage packetId={selectedPacketId} onBack={() => setPage("packets")} />
      )}
    </div>
  );
}
