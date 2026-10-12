import { ICONS } from "@/lib/icons";
import { Reveal, SectionHeading } from "@/components/home/Reveal";

// What is built and running in CyberGuard today. Every line here is backed by code and tests in the
// backend (models, watchers, IOC memory, MITRE mapping, incidents, alerts, audit log).
const CAPABILITIES = [
  {
    icon: ICONS.credential, tag: "Trained model", title: "Account-takeover detection",
    desc: "Each sign-in is compared with the account's own history of countries, networks, devices and browsers.",
    fact: "Trained on ≈31 million real logins (RBA dataset)",
  },
  {
    icon: ICONS.url, tag: "Trained model", title: "Malicious URL & website model",
    desc: "Scores the domain name, spots look-alike brands and checks the live page safely: no JavaScript, private IPs refused.",
    fact: "235,795 labelled URLs (PhiUSIIL) + Tranco top-1M",
  },
  {
    icon: ICONS.target, tag: "New", title: "MITRE ATT&CK mapping",
    desc: "Every risky scan is mapped to the attacker techniques it matches, each explained in plain language with a link to MITRE.",
    fact: "32 techniques, from phishing to credential dumping",
  },
  {
    icon: ICONS.radar, tag: "New", title: "Automatic protection",
    desc: "Checks your Gmail inbox (read-only), new downloads and Windows and CyberGuard sign-ins in the background.",
    fact: "No manual scanning needed",
  },
  {
    icon: ICONS.fingerprint, tag: "New", title: "Threat memory (IOCs)",
    desc: "Remembers bad links, domains, IPs, senders and file hashes. A repeat attack is flagged “Seen before” and scored higher.",
    fact: "Export a blocklist as CSV",
  },
  {
    icon: ICONS.warning, tag: "New", title: "Incident workflow",
    desc: "High and critical threats become incidents you move from open to investigating to resolved.",
    fact: "Tracks mean time to resolve",
  },
  {
    icon: ICONS.bell, tag: "New", title: "Instant alerts",
    desc: "Risk 71 and above is sent to Telegram, email and WhatsApp with the reasons and what to do now.",
    fact: "The same threat is alerted once per 10 minutes",
  },
  {
    icon: ICONS.scanHistory, tag: "New", title: "Activity log",
    desc: "Every sign-in, failed sign-in, settings change and incident update is recorded with IP and browser.",
    fact: "Passwords and codes are never stored",
  },
];

export function CapabilitiesSection() {
  return (
    <section id="capabilities" className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20 sm:py-24">
      <SectionHeading badge="Built and running" center title="What's Inside CyberGuard Today."
                      subtitle="Trained models on real public datasets, background protection that never stops, and a memory of every attack it has seen." />
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {CAPABILITIES.map((c, i) => (
          <Reveal key={c.title} delay={i * 0.04}>
            <div className="h-full rounded-xl border border-default bg-surface p-5 hover:border-strong transition-colors flex flex-col">
              <div className="flex items-center justify-between mb-3.5">
                <div className="h-10 w-10 rounded-lg bg-cyan-500/10 flex items-center justify-center">
                  <c.icon size={19} className="text-cyan-400" />
                </div>
                <span className={`rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${c.tag === "New" ? "bg-emerald-500/10 text-emerald-300" : "bg-cyan-500/10 text-cyan-300"}`}>
                  {c.tag}
                </span>
              </div>
              <h3 className="text-sm font-bold text-white mb-1.5">{c.title}</h3>
              <p className="text-xs text-slate-500 leading-relaxed flex-1">{c.desc}</p>
              <p className="text-[11px] font-semibold text-cyan-300 mt-3">{c.fact}</p>
            </div>
          </Reveal>
        ))}
      </div>
    </section>
  );
}
