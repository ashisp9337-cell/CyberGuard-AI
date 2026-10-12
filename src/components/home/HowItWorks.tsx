import { ICONS } from "@/lib/icons";
import { Reveal, SectionHeading } from "@/components/home/Reveal";

const STEPS = [
  { num: "01", title: "Collect", icon: ICONS.upload, desc: "Paste a message, link, email or log, upload a file, or let automatic protection pick it up from Gmail, Downloads and sign-ins." },
  { num: "02", title: "Analyze", icon: ICONS.scan, desc: "Trained models and safety checks look at the text, sender, links, files and login history, and check memory for anything seen before." },
  { num: "03", title: "Assess", icon: ICONS.gauge, desc: "A 0–100 risk score with every reason listed, mapped to the MITRE ATT&CK techniques the attacker is using." },
  { num: "04", title: "Respond", icon: ICONS.send, desc: "Clear next steps, an incident to track, and alerts on Telegram, email and WhatsApp for serious threats." },
];

export function HowItWorks() {
  return (
    <section id="how-it-works" className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20 sm:py-24">
      <SectionHeading center title="From Suspicion to Security in Four Steps." />

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 lg:gap-0 relative">
        <div className="hidden lg:block absolute top-9 left-[12.5%] right-[12.5%] h-px bg-[var(--color-border-strong)]" aria-hidden="true" />
        {STEPS.map((s, i) => (
          <Reveal key={s.num} delay={i * 0.1} className="relative flex flex-col items-center text-center px-3">
            <div className="h-[72px] w-[72px] rounded-2xl bg-surface border border-strong flex items-center justify-center mb-4 relative z-10">
              <s.icon size={26} className="text-cyan-400" />
            </div>
            <span className="text-[11px] font-mono text-slate-600 mb-1">{s.num}</span>
            <h3 className="text-sm font-bold text-white mb-1.5">{s.title}</h3>
            <p className="text-xs text-slate-500 leading-relaxed max-w-[220px]">{s.desc}</p>
          </Reveal>
        ))}
      </div>
    </section>
  );
}
