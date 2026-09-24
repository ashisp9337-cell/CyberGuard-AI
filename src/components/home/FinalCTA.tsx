import { useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/Button";
import { ICONS } from "@/lib/icons";
import { Reveal } from "@/components/home/Reveal";
import { useAuth } from "@/context/AuthContext";

export function FinalCTA() {
  const navigate = useNavigate();
  const { isAuthenticated } = useAuth();

  return (
    <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pb-20 sm:pb-24">
      <Reveal>
        <div className="relative rounded-2xl border border-cyan-500/20 bg-surface p-10 sm:p-16 text-center overflow-hidden">
          <div
            className="absolute inset-0 pointer-events-none"
            style={{ background: "radial-gradient(ellipse 70% 60% at 50% 100%, rgba(34,211,238,0.1), transparent 70%)" }}
            aria-hidden="true"
          />
          <div className="relative">
            <div className="h-12 w-12 rounded-xl bg-cyan-500/10 flex items-center justify-center mx-auto mb-5">
              <ICONS.shieldCheck size={24} className="text-cyan-400" />
            </div>
            <h2 className="text-2xl sm:text-3xl font-bold text-white tracking-tight mb-3">Your Security. Our Intelligence.</h2>
            <p className="text-sm sm:text-base text-slate-400 max-w-xl mx-auto mb-8">
              Begin exploring CyberGuard's intelligent approach to modern cyber threat detection.
            </p>
            <div className="flex flex-col sm:flex-row justify-center gap-3">
              {isAuthenticated ? (
                <Button size="lg" onClick={() => navigate("/dashboard")}>
                  Open Dashboard <ICONS.arrowRight size={16} />
                </Button>
              ) : (
                <>
                  <Button size="lg" onClick={() => navigate("/signup")}>
                    Create Free Account <ICONS.arrowRight size={16} />
                  </Button>
                  <Button size="lg" variant="secondary" onClick={() => navigate("/signin")}>
                    Sign In
                  </Button>
                </>
              )}
            </div>
          </div>
        </div>
      </Reveal>
    </section>
  );
}
