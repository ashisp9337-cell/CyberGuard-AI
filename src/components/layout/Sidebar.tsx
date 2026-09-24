import { NavLink, useNavigate } from "react-router-dom";
import { ICONS } from "@/lib/icons";
import { DETECTION_MODULES } from "@/data/modules";
import { useAppContext } from "@/context/AppContext";
import { useAuth } from "@/context/AuthContext";
import { cn } from "@/lib/utils";

const MAIN_NAV = [
  { to: "/dashboard", label: "Dashboard", icon: ICONS.dashboard, end: true },
  { to: "/threat-overview", label: "Threat Overview", icon: ICONS.threatOverview },
  { to: "/modules", label: "Detection Modules", icon: ICONS.shieldCheck },
  { to: "/live-monitoring", label: "Live Monitoring", icon: ICONS.liveMonitoring },
  { to: "/threat-intelligence", label: "Threat Intelligence", icon: ICONS.threatIntel },
  { to: "/scan-history", label: "Scan History", icon: ICONS.scanHistory },
  { to: "/reports", label: "Reports", icon: ICONS.reports },
];

const SYSTEM_NAV = [
  { to: "/settings", label: "Settings", icon: ICONS.settings },
  { to: "/help", label: "Help & Documentation", icon: ICONS.help },
];

function NavItem({ to, label, Icon, end, collapsed, onClick }: { to: string; label: string; Icon: any; end?: boolean; collapsed: boolean; onClick?: () => void }) {
  return (
    <NavLink
      to={to}
      end={end}
      onClick={onClick}
      className={({ isActive }) =>
        cn(
          "flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors focus-ring group relative",
          isActive ? "bg-cyan-500/10 text-cyan-300" : "text-fg-muted hover:text-fg hover:bg-elevated"
        )
      }
      title={collapsed ? label : undefined}
    >
      {({ isActive }) => (
        <>
          {isActive && <span className="absolute left-0 top-1.5 bottom-1.5 w-0.5 rounded-full bg-cyan-400" aria-hidden="true" />}
          <Icon size={17} className="shrink-0" aria-hidden="true" />
          {!collapsed && <span className="truncate">{label}</span>}
        </>
      )}
    </NavLink>
  );
}

export function Sidebar({ variant = "desktop" }: { variant?: "desktop" | "mobile" }) {
  const { sidebarCollapsed, mobileNavOpen, setMobileNavOpen } = useAppContext();
  const { signOut } = useAuth();
  const navigate = useNavigate();
  const collapsed = variant === "desktop" && sidebarCollapsed;

  async function handleLogout() {
    setMobileNavOpen(false);
    await signOut();
    navigate("/", { replace: true });
  }

  if (variant === "mobile" && !mobileNavOpen) return null;

  const content = (
    <nav className="flex flex-col h-full" aria-label="Primary">
      <div className={cn("flex items-center gap-2.5 px-4 h-16 border-b border-default shrink-0", collapsed && "justify-center px-2")}>
        <div className="h-8 w-8 rounded-lg bg-cyan-500/15 flex items-center justify-center shrink-0">
          <ICONS.shieldCheck size={18} className="text-cyan-400" />
        </div>
        {!collapsed && (
          <div className="min-w-0">
            <p className="text-sm font-bold text-fg tracking-tight leading-none">CYBERGUARD AI</p>
            <p className="text-[10px] text-fg-muted mt-0.5">Threat Intelligence Platform</p>
          </div>
        )}
      </div>

      <div className="flex-1 overflow-y-auto px-3 py-4 space-y-6">
        <div className="space-y-1">
          {!collapsed && <p className="px-3 text-[10px] font-semibold uppercase tracking-wider text-fg-faint mb-1.5">Main</p>}
          {MAIN_NAV.map((item) => (
            <NavItem key={item.to} to={item.to} label={item.label} Icon={item.icon} end={item.end} collapsed={collapsed} onClick={() => setMobileNavOpen(false)} />
          ))}
        </div>

        <div className="space-y-1">
          {!collapsed && <p className="px-3 text-[10px] font-semibold uppercase tracking-wider text-fg-faint mb-1.5">Detection Modules</p>}
          {DETECTION_MODULES.map((mod) => {
            const Icon = ICONS[mod.icon as keyof typeof ICONS] ?? ICONS.shieldCheck;
            return (
              <NavItem
                key={mod.id}
                to={`/modules/${mod.id}`}
                label={mod.shortName}
                Icon={Icon}
                collapsed={collapsed}
                onClick={() => setMobileNavOpen(false)}
              />
            );
          })}
        </div>

        <div className="space-y-1">
          {!collapsed && <p className="px-3 text-[10px] font-semibold uppercase tracking-wider text-fg-faint mb-1.5">System</p>}
          {SYSTEM_NAV.map((item) => (
            <NavItem key={item.to} to={item.to} label={item.label} Icon={item.icon} collapsed={collapsed} onClick={() => setMobileNavOpen(false)} />
          ))}
        </div>
      </div>

      <div className={cn("border-t border-default p-3 shrink-0", collapsed && "flex justify-center")}>
        <button className={cn("flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm text-fg-muted hover:text-fg hover:bg-elevated w-full focus-ring", collapsed && "w-auto justify-center")} onClick={handleLogout}>
          <ICONS.logout size={16} />
          {!collapsed && <span>Logout</span>}
        </button>
      </div>
    </nav>
  );

  if (variant === "mobile") {
    return (
      <div className="fixed inset-0 z-50 lg:hidden">
        <div className="absolute inset-0 bg-black/60" onClick={() => setMobileNavOpen(false)} aria-hidden="true" />
        <div className="absolute left-0 top-0 bottom-0 w-72 bg-surface border-r border-default shadow-2xl">
          <button
            onClick={() => setMobileNavOpen(false)}
            aria-label="Close navigation"
            className="absolute right-3 top-4 text-fg-muted hover:text-fg focus-ring rounded p-1"
          >
            <ICONS.close size={18} />
          </button>
          {content}
        </div>
      </div>
    );
  }

  return (
    <aside
      className={cn(
        "hidden lg:flex flex-col border-r border-default bg-surface shrink-0 transition-all duration-200 sticky top-0 h-screen",
        collapsed ? "w-[76px]" : "w-64"
      )}
    >
      {content}
    </aside>
  );
}
