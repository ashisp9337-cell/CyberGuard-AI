import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { AnimatePresence, motion } from "framer-motion";
import { ICONS } from "@/lib/icons";
import { Button } from "@/components/ui/Button";
import { cn } from "@/lib/utils";
import { useAuth } from "@/context/AuthContext";

const NAV_LINKS = [
  { label: "Platform", href: "#platform" },
  { label: "Solutions", href: "#solution" },
  { label: "How It Works", href: "#how-it-works" },
  { label: "Technology", href: "#technology" },
  { label: "About", href: "#about" },
];

export function HomeNavbar() {
  const navigate = useNavigate();
  const { isAuthenticated } = useAuth();
  const [scrolled, setScrolled] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 8);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  function handleNavClick(href: string) {
    setMobileOpen(false);
    const el = document.querySelector(href);
    el?.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  return (
    <header
      className={cn(
        "sticky top-0 z-50 transition-colors duration-200",
        scrolled ? "bg-canvas/85 backdrop-blur border-b border-default" : "bg-transparent border-b border-transparent"
      )}
    >
      <nav aria-label="Main" className="max-w-7xl mx-auto flex items-center gap-4 px-4 sm:px-6 lg:px-8 h-16">
        <button
          onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}
          className="flex items-center gap-2.5 focus-ring rounded-lg shrink-0"
          aria-label="CyberGuard AI — scroll to top"
        >
          <div className="h-8 w-8 rounded-lg bg-cyan-500/15 flex items-center justify-center">
            <ICONS.shieldCheck size={18} className="text-cyan-400" />
          </div>
          <span className="text-sm font-bold text-white tracking-tight">CYBERGUARD AI</span>
        </button>

        <div className="hidden lg:flex items-center gap-1 mx-auto">
          {NAV_LINKS.map((link) => (
            <button
              key={link.href}
              onClick={() => handleNavClick(link.href)}
              className="px-3.5 py-2 rounded-lg text-sm font-medium text-slate-400 hover:text-white hover:bg-elevated transition-colors focus-ring"
            >
              {link.label}
            </button>
          ))}
        </div>

        <div className="hidden lg:flex items-center gap-2 ml-auto">
          {isAuthenticated ? (
            <Button onClick={() => navigate("/dashboard")}>
              Open Dashboard <ICONS.arrowRight size={15} />
            </Button>
          ) : (
            <>
              <Button variant="ghost" onClick={() => navigate("/signin")}>
                Sign In
              </Button>
              <Button onClick={() => navigate("/signup")}>
                Get Started <ICONS.arrowRight size={15} />
              </Button>
            </>
          )}
        </div>

        <button
          onClick={() => setMobileOpen((v) => !v)}
          className="lg:hidden ml-auto text-slate-300 hover:text-white focus-ring rounded p-1.5"
          aria-label={mobileOpen ? "Close menu" : "Open menu"}
          aria-expanded={mobileOpen}
        >
          {mobileOpen ? <ICONS.close size={22} /> : <ICONS.menu size={22} />}
        </button>
      </nav>

      <AnimatePresence>
        {mobileOpen && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="lg:hidden overflow-hidden border-b border-default bg-canvas"
          >
            <div className="px-4 sm:px-6 py-3 flex flex-col gap-1">
              {NAV_LINKS.map((link) => (
                <button
                  key={link.href}
                  onClick={() => handleNavClick(link.href)}
                  className="text-left px-3 py-2.5 rounded-lg text-sm font-medium text-slate-300 hover:text-white hover:bg-elevated focus-ring"
                >
                  {link.label}
                </button>
              ))}
              <Button className="mt-2 w-full" onClick={() => navigate(isAuthenticated ? "/dashboard" : "/signup")}>
                {isAuthenticated ? "Open Dashboard" : "Get Started"} <ICONS.arrowRight size={15} />
              </Button>
              {!isAuthenticated && (
                <Button variant="secondary" className="w-full" onClick={() => navigate("/signin")}>
                  Sign In
                </Button>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </header>
  );
}
