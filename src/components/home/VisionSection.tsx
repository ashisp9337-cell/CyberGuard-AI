import { ICONS } from "@/lib/icons";
import { Reveal } from "@/components/home/Reveal";

export function VisionSection() {
  return (
    <section className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-16" id="vision">
      <Reveal>
        <div className="relative rounded-2xl border border-default bg-surface p-8 sm:p-12 text-center overflow-hidden">
          <div
            className="absolute inset-0 pointer-events-none"
            style={{ background: "radial-gradient(ellipse 60% 60% at 50% 50%, rgba(34,211,238,0.06), transparent 70%)" }}
            aria-hidden="true"
          />
          <div className="relative">
            <div className="h-12 w-12 rounded-xl bg-cyan-500/10 flex items-center justify-center mx-auto mb-5">
              <ICONS.eye size={22} className="text-cyan-400" />
            </div>
            <h2 className="text-2xl sm:text-3xl font-bold text-white tracking-tight mb-4">Our Vision</h2>
            <p className="text-base text-slate-300 font-medium leading-relaxed max-w-2xl mx-auto">
              "To create a safer digital world where intelligent security systems can identify, understand, and
              respond to emerging threats before they cause harm."
            </p>
            <p className="text-sm text-slate-500 leading-relaxed max-w-xl mx-auto mt-5">
              CyberGuard envisions a future where cybersecurity is not only reactive, but proactive, intelligent,
              accessible, and capable of adapting to the rapidly evolving digital threat landscape.
            </p>
          </div>
        </div>
      </Reveal>
    </section>
  );
}
