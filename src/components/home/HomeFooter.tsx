import { Link } from "react-router-dom";
import { ICONS } from "@/lib/icons";

const GROUPS = [
  {
    title: "Product",
    links: [
      { label: "Platform", href: "#platform" },
      { label: "Detection Modules", to: "/modules" },
      { label: "Dashboard", to: "/dashboard" },
      { label: "Threat Intelligence", to: "/threat-intelligence" },
    ],
  },
  {
    title: "Company",
    links: [
      { label: "About", href: "#about" },
      { label: "Vision", href: "#vision" },
      { label: "Mission", href: "#mission" },
    ],
  },
  {
    title: "Resources",
    links: [
      { label: "Help", to: "/help" },
      { label: "Security Architecture", href: "#technology" },
      { label: "Platform Overview", href: "#platform" },
    ],
  },
];

export function HomeFooter() {
  return (
    <footer className="border-t border-default bg-surface/60">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-14">
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-8">
          <div className="col-span-2 sm:col-span-1">
            <div className="flex items-center gap-2 mb-3">
              <div className="h-7 w-7 rounded-lg bg-cyan-500/15 flex items-center justify-center">
                <ICONS.shieldCheck size={15} className="text-cyan-400" />
              </div>
              <span className="text-sm font-bold text-white tracking-tight">CYBERGUARD AI</span>
            </div>
            <p className="text-xs text-slate-500 leading-relaxed max-w-[220px]">
              AI-powered cybersecurity intelligence for modern digital threats.
            </p>
          </div>

          {GROUPS.map((group) => (
            <div key={group.title}>
              <p className="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-3">{group.title}</p>
              <ul className="space-y-2">
                {group.links.map((link) => (
                  <li key={link.label}>
                    {"to" in link && link.to ? (
                      <Link to={link.to} className="text-sm text-slate-400 hover:text-white focus-ring rounded transition-colors">
                        {link.label}
                      </Link>
                    ) : (
                      <a
                        href={link.href}
                        className="text-sm text-slate-400 hover:text-white focus-ring rounded transition-colors"
                      >
                        {link.label}
                      </a>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>

        <div className="flex flex-col sm:flex-row items-center justify-between gap-3 mt-12 pt-6 border-t border-default">
          <p className="text-xs text-slate-600">© 2026 CyberGuard AI. All rights reserved.</p>
          <div className="flex gap-5">
            <span className="text-xs text-slate-600">Privacy</span>
            <span className="text-xs text-slate-600">Terms</span>
          </div>
        </div>
      </div>
    </footer>
  );
}
