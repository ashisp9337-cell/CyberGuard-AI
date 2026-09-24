import { motion, useReducedMotion, type Variants } from "framer-motion";
import type { ReactNode } from "react";

export function Reveal({
  children,
  delay = 0,
  y = 16,
  className,
}: {
  children: ReactNode;
  delay?: number;
  y?: number;
  className?: string;
}) {
  const reduceMotion = useReducedMotion();
  const variants: Variants = {
    hidden: { opacity: 0, y: reduceMotion ? 0 : y },
    visible: { opacity: 1, y: 0, transition: { duration: 0.5, delay, ease: "easeOut" } },
  };
  return (
    <motion.div
      className={className}
      initial="hidden"
      whileInView="visible"
      viewport={{ once: true, margin: "-60px" }}
      variants={variants}
    >
      {children}
    </motion.div>
  );
}

export function SectionBadge({ children }: { children: ReactNode }) {
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border border-cyan-500/25 bg-cyan-500/10 px-3 py-1 text-[11px] font-semibold uppercase tracking-wider text-cyan-300">
      {children}
    </span>
  );
}

export function SectionHeading({
  badge,
  title,
  subtitle,
  center = false,
}: {
  badge?: string;
  title: string;
  subtitle?: string;
  center?: boolean;
}) {
  return (
    <Reveal className={center ? "text-center max-w-2xl mx-auto mb-12" : "max-w-2xl mb-12"}>
      {badge && (
        <div className={center ? "flex justify-center mb-4" : "mb-4"}>
          <SectionBadge>{badge}</SectionBadge>
        </div>
      )}
      <h2 className="text-2xl sm:text-3xl font-bold text-white tracking-tight leading-tight">{title}</h2>
      {subtitle && <p className="text-sm sm:text-base text-slate-400 mt-3 leading-relaxed">{subtitle}</p>}
    </Reveal>
  );
}
