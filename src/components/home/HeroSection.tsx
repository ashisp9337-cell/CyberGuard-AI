import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { Button } from "@/components/ui/Button";
import { ICONS } from "@/lib/icons";
import { Reveal } from "@/components/home/Reveal";
import { useAuth } from "@/context/AuthContext";

const ORBIT_NODES = [
  { icon: ICONS.email, label: "Phishing", angle: -90, color: "#f97316" },
  { icon: ICONS.video, label: "Deepfake", angle: -30, color: "#a855f7" },
  { icon: ICONS.impersonation, label: "Impersonation", angle: 30, color: "#eab308" },
  { icon: ICONS.credential, label: "Credential Theft", angle: 90, color: "#38bdf8" },
  { icon: ICONS.url, label: "Malicious URLs", angle: 150, color: "#22c55e" },
  { icon: ICONS.malware, label: "Cyber Threats", angle: 210, color: "#ef4444" },
];

const RADIUS = 150;

function HeroVisual() {
  return (
    <div className="relative mx-auto h-[340px] w-[340px] sm:h-[400px] sm:w-[400px]" aria-hidden="true">
      {/* concentric rings */}
      <div className="absolute inset-0 rounded-full border border-cyan-500/10" />
      <div className="absolute inset-8 rounded-full border border-cyan-500/10" />
      <div className="absolute inset-16 rounded-full border border-cyan-500/15" />

      {/* connecting lines */}
      <svg className="absolute inset-0 h-full w-full" viewBox="-200 -200 400 400">
        {ORBIT_NODES.map((node, i) => {
          const rad = (node.angle * Math.PI) / 180;
          const x = Math.cos(rad) * RADIUS;
          const y = Math.sin(rad) * RADIUS;
          return (
            <line
              key={i}
              x1={0}
              y1={0}
              x2={x}
              y2={y}
              stroke={node.color}
              strokeOpacity={0.25}
              strokeWidth={1}
              strokeDasharray="4 4"
            />
          );
        })}
      </svg>

      {/* central core */}
      <motion.div
        className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 h-24 w-24 rounded-2xl bg-elevated border border-strong flex items-center justify-center shadow-2xl"
        animate={{ boxShadow: ["0 0 0 0 rgba(34,211,238,0.25)", "0 0 0 14px rgba(34,211,238,0)"] }}
        transition={{ duration: 2.4, repeat: Infinity, ease: "easeOut" }}
      >
        <ICONS.shieldCheck size={38} className="text-cyan-400" />
      </motion.div>

      {/* orbit nodes */}
      {ORBIT_NODES.map((node, i) => {
        const rad = (node.angle * Math.PI) / 180;
        const x = Math.cos(rad) * RADIUS;
        const y = Math.sin(rad) * RADIUS;
        const Icon = node.icon;
        return (
          <motion.div
            key={node.label}
            className="absolute left-1/2 top-1/2 flex flex-col items-center gap-1.5"
            style={{ marginLeft: x - 26, marginTop: y - 26 }}
            animate={{ y: [0, -5, 0] }}
            transition={{ duration: 3 + i * 0.3, repeat: Infinity, ease: "easeInOut", delay: i * 0.2 }}
          >
            <div
              className="h-[52px] w-[52px] rounded-xl flex items-center justify-center border"
              style={{ backgroundColor: `${node.color}1a`, borderColor: `${node.color}40`, color: node.color }}
            >
              <Icon size={22} />
            </div>
            <span className="hidden sm:block text-[10px] font-medium text-slate-500 whitespace-nowrap">{node.label}</span>
          </motion.div>
        );
      })}
    </div>
  );
}

export function HeroSection() {
  const navigate = useNavigate();
  const { isAuthenticated } = useAuth();

  function scrollToPlatform() {
    document.querySelector("#platform")?.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  return (
    <section className="relative overflow-hidden">
      <div
        className="absolute inset-0 pointer-events-none"
        style={{ background: "radial-gradient(ellipse 60% 50% at 50% 0%, rgba(34,211,238,0.08), transparent 70%)" }}
        aria-hidden="true"
      />
      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-16 pb-20 sm:pt-24 sm:pb-28 grid lg:grid-cols-2 gap-12 items-center">
        <Reveal>
          <span className="inline-flex items-center gap-1.5 rounded-full border border-cyan-500/25 bg-cyan-500/10 px-3 py-1 text-[11px] font-semibold uppercase tracking-wider text-cyan-300 mb-6">
            <ICONS.brain size={13} /> AI-Powered Cybersecurity Platform
          </span>
          <h1 className="text-3xl sm:text-4xl lg:text-[2.75rem] font-extrabold text-white tracking-tight leading-[1.1]">
            Protect What Matters Before Threats Strike.
          </h1>
          <p className="text-base text-slate-400 mt-5 leading-relaxed max-w-xl">
            CyberGuard is an intelligent cybersecurity platform designed to detect, analyze, and assess modern digital
            threats — from phishing and malware to deepfakes, impersonation, account takeovers, malicious URLs, and
            suspicious cyber activity.
          </p>
          <p className="text-sm font-semibold text-cyan-300 mt-4 tracking-wide">
            Detect the Threat. Understand the Risk. Stay Protected.
          </p>

          <div className="flex flex-col sm:flex-row gap-3 mt-8">
            {isAuthenticated ? (
              <Button size="lg" onClick={() => navigate("/dashboard")}>
                <ICONS.dashboard size={16} /> Open Security Dashboard
              </Button>
            ) : (
              <Button size="lg" onClick={() => navigate("/signup")}>
                Get Started <ICONS.arrowRight size={16} />
              </Button>
            )}
            <Button size="lg" variant="secondary" onClick={scrollToPlatform}>
              Explore the Platform
            </Button>
          </div>

          <div className="flex flex-wrap gap-x-6 gap-y-2 mt-8">
            {["Multi-Layer Detection", "Explainable AI", "Intelligent Threat Analysis"].map((v) => (
              <span key={v} className="flex items-center gap-1.5 text-xs font-medium text-slate-400">
                <ICONS.success size={14} className="text-emerald-400" /> {v}
              </span>
            ))}
          </div>
        </Reveal>

        <Reveal delay={0.15}>
          <HeroVisual />
        </Reveal>
      </div>
    </section>
  );
}
