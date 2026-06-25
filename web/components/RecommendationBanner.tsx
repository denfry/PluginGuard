import type { ReactNode } from "react";
import type { Recommendation, RecommendationLevel } from "@/lib/types";
import { RECOMMENDATION_LABEL } from "@/lib/format";
import { CheckIcon, ShieldIcon, AlertIcon } from "./icons";

/**
 * The report's headline: the single action a reader came for ("Do not install").
 * Styled as a forensic determination — a loud, colour-coded band at the very top
 * of the report so the verdict outweighs every analytical detail beneath it.
 */
interface Tone {
  /** Accent hex, used for the edge rule, icon and ambient glow. */
  accent: string;
  text: string;
  border: string;
  bg: string;
  icon: ReactNode;
  /** Hazard hatching for the two determinations that should stop a reader cold. */
  hazard: boolean;
}

const ICON_CLS = "h-6 w-6";

const TONES: Record<RecommendationLevel, Tone> = {
  SAFE_TO_INSTALL: {
    accent: "#a3e635",
    text: "text-primary",
    border: "border-primary/40",
    bg: "from-primary/12",
    icon: <CheckIcon className={ICON_CLS} />,
    hazard: false,
  },
  INSTALL_WITH_CARE: {
    accent: "#38bdf8",
    text: "text-info",
    border: "border-info/40",
    bg: "from-info/12",
    icon: <ShieldIcon className={ICON_CLS} />,
    hazard: false,
  },
  RISKY: {
    accent: "#fbbf24",
    text: "text-warning",
    border: "border-warning/40",
    bg: "from-warning/12",
    icon: <AlertIcon className={ICON_CLS} />,
    hazard: false,
  },
  AVOID: {
    accent: "#fb7185",
    text: "text-danger",
    border: "border-danger/40",
    bg: "from-danger/12",
    icon: <AlertIcon className={ICON_CLS} />,
    hazard: true,
  },
  DO_NOT_INSTALL: {
    accent: "#fb7185",
    text: "text-danger",
    border: "border-danger/40",
    bg: "from-danger/12",
    icon: <AlertIcon className={ICON_CLS} />,
    hazard: true,
  },
};

export function RecommendationBanner({ rec }: { rec: Recommendation }) {
  const tone = TONES[rec.level];
  const reasons = rec.perAxis.slice(0, 3);

  return (
    <section
      className={`reveal relative overflow-hidden rounded-xl border ${tone.border} bg-gradient-to-r ${tone.bg} to-transparent`}
      style={{ boxShadow: `0 0 50px -28px ${tone.accent}` }}
      aria-label={`Recommendation: ${RECOMMENDATION_LABEL[rec.level]}`}
    >
      {/* Coloured determination rule down the leading edge. */}
      <span
        aria-hidden
        className="absolute inset-y-0 left-0 w-1"
        style={{ backgroundColor: tone.accent }}
      />
      {/* Hazard hatching for AVOID / DO NOT INSTALL — kept very low-contrast. */}
      {tone.hazard && (
        <span
          aria-hidden
          className="pointer-events-none absolute inset-0 opacity-[0.06]"
          style={{
            backgroundImage: `repeating-linear-gradient(-45deg, ${tone.accent} 0 1px, transparent 1px 11px)`,
          }}
        />
      )}

      <div className="relative flex flex-col gap-5 p-6 sm:flex-row sm:items-center sm:gap-6 lg:p-7">
        <span
          className={`flex h-12 w-12 shrink-0 items-center justify-center rounded-lg border ${tone.border} ${tone.text}`}
          style={{ backgroundColor: `${tone.accent}1a` }}
        >
          {tone.icon}
        </span>

        <div className="min-w-0 flex-1">
          <p className="micro-label text-faint">Recommendation</p>
          <p
            className={`mt-1 font-display text-2xl font-semibold leading-tight tracking-tight lg:text-[1.75rem] ${tone.text}`}
          >
            {RECOMMENDATION_LABEL[rec.level]}
          </p>
          <p className="mt-1.5 max-w-2xl text-sm leading-relaxed text-muted">
            {rec.headline}
          </p>
        </div>

        {reasons.length > 0 && (
          <ul className="shrink-0 space-y-1.5 border-line pt-1 sm:max-w-[18rem] sm:border-l sm:pl-6">
            {reasons.map((r) => (
              <li
                key={r}
                className="flex gap-2 text-xs leading-snug text-muted"
              >
                <span
                  aria-hidden
                  className="mt-1 h-1 w-1 shrink-0 rounded-full"
                  style={{ backgroundColor: tone.accent }}
                />
                {r}
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}
