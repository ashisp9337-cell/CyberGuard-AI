import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { AnimatePresence, motion } from "framer-motion";
import { ICONS } from "@/lib/icons";
import { ThemeToggle } from "@/components/layout/ThemeToggle";
import { useAppContext } from "@/context/AppContext";
import { useAuth } from "@/context/AuthContext";
import { getUnreadCount, markAllRead } from "@/services/api/eventsService";

function initials(name: string) {
  const parts = name.trim().split(/\s+/);
  return ((parts[0]?.[0] ?? "") + (parts[1]?.[0] ?? "")).toUpperCase() || "U";
}

export function Topbar() {
  const { toggleSidebar, setMobileNavOpen, sidebarCollapsed } = useAppContext();
  const { user, signOut } = useAuth();
  const [query, setQuery] = useState("");
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();
  const [unreadCount, setUnreadCount] = useState(0);

  useEffect(() => {
    let cancelled = false;
    const load = () => getUnreadCount().then((c) => !cancelled && setUnreadCount(c)).catch(() => {});
    load();
    const interval = setInterval(load, 15000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  async function handleBellClick() {
    await markAllRead().catch(() => {});
    setUnreadCount(0);
    navigate("/live-monitoring");
  }

  useEffect(() => {
    function onClickOutside(e: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) setMenuOpen(false);
    }
    document.addEventListener("mousedown", onClickOutside);
    return () => document.removeEventListener("mousedown", onClickOutside);
  }, []);

  function handleSearch(e: React.FormEvent) {
    e.preventDefault();
    if (query.trim()) navigate("/scan-history", { state: { search: query } });
  }

  async function handleSignOut() {
    setMenuOpen(false);
    await signOut();
    navigate("/", { replace: true });
  }

  return (
    <header className="sticky top-0 z-30 h-16 border-b border-default bg-surface/90 backdrop-blur flex items-center gap-3 px-4 lg:px-6 shrink-0">
      <button
        onClick={() => setMobileNavOpen(true)}
        className="lg:hidden text-fg-muted hover:text-fg focus-ring rounded p-1.5"
        aria-label="Open navigation menu"
      >
        <ICONS.menu size={20} />
      </button>
      <button
        onClick={toggleSidebar}
        className="hidden lg:flex text-fg-muted hover:text-fg focus-ring rounded p-1.5"
        aria-label={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
      >
        <ICONS.menu size={18} />
      </button>

      <form onSubmit={handleSearch} className="flex-1 max-w-md">
        <div className="relative">
          <ICONS.search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-fg-muted" />
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search threats, files, URLs, reports..."
            aria-label="Global search"
            className="w-full rounded-lg bg-elevated border border-strong pl-9 pr-3 py-2 text-sm text-fg placeholder:text-fg-faint focus-ring"
          />
        </div>
      </form>

      <div className="flex-1" />

      <div className="hidden sm:flex items-center gap-2 rounded-full bg-elevated border border-default px-3 py-1.5">
        <span className="h-2 w-2 rounded-full bg-emerald-400 pulse-live" aria-hidden="true" />
        <span className="text-xs font-semibold text-emerald-400 tracking-wide">SYSTEM PROTECTED</span>
      </div>

      <ThemeToggle />

      <button
        onClick={handleBellClick}
        className="relative text-fg-muted hover:text-fg focus-ring rounded-lg p-2 hover:bg-elevated"
        aria-label={`View active threats (${unreadCount})`}
      >
        <ICONS.bell size={18} />
        {unreadCount > 0 && (
          <span className="absolute -top-0.5 -right-0.5 h-4 min-w-[1rem] px-0.5 rounded-full bg-red-500 text-[9px] font-bold text-white flex items-center justify-center">
            {unreadCount > 99 ? "99+" : unreadCount}
          </span>
        )}
      </button>

      <div className="relative" ref={menuRef}>
        <button
          onClick={() => setMenuOpen((v) => !v)}
          className="flex items-center gap-2 rounded-lg pl-1 pr-2 py-1 hover:bg-elevated focus-ring"
          aria-label="User profile menu"
          aria-expanded={menuOpen}
        >
          {user?.avatarUrl ? (
            <img src={user.avatarUrl} alt="" className="h-8 w-8 rounded-full object-cover" referrerPolicy="no-referrer" />
          ) : (
            <div className="h-8 w-8 rounded-full bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center text-xs font-bold text-white">
              {initials(user?.name ?? "User")}
            </div>
          )}
          <span className="hidden md:block text-sm text-fg-secondary max-w-[120px] truncate">{user?.name ?? "Account"}</span>
          <ICONS.chevronDown size={14} className="hidden md:block text-fg-muted" />
        </button>

        <AnimatePresence>
          {menuOpen && (
            <motion.div
              initial={{ opacity: 0, y: -6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -6 }}
              transition={{ duration: 0.15 }}
              className="absolute right-0 mt-2 w-60 rounded-xl border border-strong bg-elevated shadow-2xl p-1.5 z-40"
            >
              <div className="px-3 py-2.5 border-b border-default mb-1">
                <p className="text-sm font-semibold text-fg truncate">{user?.name}</p>
                <p className="text-xs text-fg-muted truncate mt-0.5">{user?.email}</p>
              </div>
              <button
                onClick={() => {
                  setMenuOpen(false);
                  navigate("/settings");
                }}
                className="w-full flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm text-fg-secondary hover:text-fg hover:bg-hover-surface focus-ring text-left"
              >
                <ICONS.settings size={15} /> Settings
              </button>
              <button
                onClick={handleSignOut}
                className="w-full flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm text-red-400 hover:bg-red-500/10 focus-ring text-left"
              >
                <ICONS.logout size={15} /> Sign Out
              </button>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </header>
  );
}
