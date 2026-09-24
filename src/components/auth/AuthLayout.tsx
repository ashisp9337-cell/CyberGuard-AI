import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import { ICONS } from "@/lib/icons";
import type { ReactNode } from "react";

const ORBIT_NODES = [
  { icon: ICONS.email, angle: -90, color: "#f97316" },
  { icon: ICONS.video, angle: -30, color: "#a855f7" },
  { icon: ICONS.credential, angle: 30, color: "#38bdf8" },
  { icon: ICONS.url, angle: 90, color: "#22c55e" },
  { icon: ICONS.malware, angle: 150, color: "#ef4444" },
  { icon: ICONS.impersonation, angle: 210, color: "#eab308" },
];
const RADIUS = 120;

function SecurityVisual() {
  return (
    <div className="relative h-[300px] w-[300px]" aria-hidden="true">
      <div className="absolute inset-0 rounded-full border border-cyan-500/10" />
      <div className="absolute inset-10 rounded-full border border-cyan-500/15" />
      <svg className="absolute inset-0 h-full w-full" viewBox="-150 -150 300 300">
        {ORBIT_NODES.map((node, i) => {
          const rad = (node.angle * Math.PI) / 180;
          return (
            <line
              key={i}
              x1={0}
              y1={0}
              x2={Math.cos(rad) * RADIUS}
              y2={Math.sin(rad) * RADIUS}
              stroke={node.color}
              strokeOpacity={0.25}
              strokeWidth={1}
              strokeDasharray="4 4"
            />
          );
        })}
      </svg>
      <motion.div
        className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 h-20 w-20 rounded-2xl bg-elevated border border-strong flex items-center justify-center"
        animate={{ boxShadow: ["0 0 0 0 rgba(34,211,238,0.25)", "0 0 0 12px rgba(34,211,238,0)"] }}
        transition={{ duration: 2.4, repeat: Infinity, ease: "easeOut" }}
      >
        <ICONS.shieldCheck size={32} className="text-cyan-400" />
      </motion.div>
      {ORBIT_NODES.map((node, i) => {
        const rad = (node.angle * Math.PI) / 180;
        const x = Math.cos(rad) * RADIUS;
        const y = Math.sin(rad) * RADIUS;
        const Icon = node.icon;
        return (
          <motion.div
            key={i}
            className="absolute left-1/2 top-1/2 h-11 w-11 rounded-xl flex items-center justify-center border"
            style={{ marginLeft: x - 22, marginTop: y - 22, backgroundColor: `${node.color}1a`, borderColor: `${node.color}40`, color: node.color }}
            animate={{ y: [0, -5, 0] }}
            transition={{ duration: 3 + i * 0.3, repeat: Infinity, ease: "easeInOut", delay: i * 0.2 }}
          >
            <Icon size={18} />
          </motion.div>
        );
      })}
    </div>
  );
}

export function AuthLayout({ children }: { children: ReactNode }) {
  return (
    <div className="min-h-screen bg-canvas grid lg:grid-cols-2">
      <div className="flex flex-col px-4 sm:px-8 lg:px-16 py-10">
        <Link to="/" className="flex items-center gap-2.5 focus-ring rounded-lg w-fit mb-10">
          <div className="h-8 w-8 rounded-lg bg-cyan-500/15 flex items-center justify-center">
            <ICONS.shieldCheck size={18} className="text-cyan-400" />
          </div>
          <span className="text-sm font-bold text-white tracking-tight">CYBERGUARD AI</span>
        </Link>

        <div className="flex-1 flex items-center justify-center">
          <div className="w-full max-w-sm">{children}</div>
        </div>
      </div>

      <div className="hidden lg:flex relative items-center justify-center border-l border-default bg-surface overflow-hidden">
        <div
          className="absolute inset-0 pointer-events-none"
          style={{ background: "radial-gradient(ellipse 60% 50% at 50% 50%, rgba(34,211,238,0.08), transparent 70%)" }}
          aria-hidden="true"
        />
        <div className="relative text-center">
          <SecurityVisual />
          <p className="text-sm font-semibold text-cyan-300 mt-4 tracking-wide max-w-xs mx-auto">
            Detect the Threat. Understand the Risk. Stay Protected.
          </p>
          <p className="text-xs text-slate-500 mt-2 max-w-xs mx-auto">
            Multi-layer AI-assisted analysis across phishing, deepfakes, impersonation, credential theft, malicious URLs, and cyber threats.
          </p>
        </div>
      </div>
    </div>
  );
}
