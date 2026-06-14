"use client";

import { useEffect, useState } from "react";
import { scoreStroke } from "@/lib/format";
import { useI18n } from "@/lib/i18n";

const CENTER = 100;
const RADIUS = 78;
const START_ANGLE = 135; // bottom-left, sweeping clockwise over the top
const SWEEP = 270;

function polar(angleDeg: number, radius: number): [number, number] {
  const a = (angleDeg * Math.PI) / 180;
  // Round to fixed precision so server- and client-rendered SVG attributes serialize identically
  // (full-precision floats stringify differently across runtimes and trigger hydration warnings).
  const round = (n: number) => Math.round(n * 1000) / 1000;
  return [round(CENTER + radius * Math.cos(a)), round(CENTER + radius * Math.sin(a))];
}

function arcPath(fromDeg: number, toDeg: number, radius: number): string {
  const [x1, y1] = polar(fromDeg, radius);
  const [x2, y2] = polar(toDeg, radius);
  const largeArc = toDeg - fromDeg > 180 ? 1 : 0;
  return `M ${x1.toFixed(2)} ${y1.toFixed(2)} A ${radius} ${radius} 0 ${largeArc} 1 ${x2.toFixed(2)} ${y2.toFixed(2)}`;
}

/** Graduation ticks: a major line every 10 points, a minor one every 5. */
function Ticks() {
  const ticks = [];
  for (let value = 0; value <= 100; value += 5) {
    const angle = START_ANGLE + (value / 100) * SWEEP;
    const major = value % 10 === 0;
    const [x1, y1] = polar(angle, major ? 88 : 91);
    const [x2, y2] = polar(angle, 94);
    ticks.push(
      <line
        key={value}
        x1={x1}
        y1={y1}
        x2={x2}
        y2={y2}
        stroke="currentColor"
        strokeWidth={major ? 1.5 : 1}
        className={major ? "text-line-strong" : "text-line"}
      />,
    );
  }
  return <>{ticks}</>;
}

export function ScoreGauge({ score }: { score: number }) {
  const { t } = useI18n();
  const clamped = Math.max(0, Math.min(100, score));
  const stroke = scoreStroke(clamped);
  // Start at zero and let the CSS transition sweep the needle up on mount.
  const [shown, setShown] = useState(0);

  useEffect(() => {
    const id = requestAnimationFrame(() => setShown(clamped));
    return () => cancelAnimationFrame(id);
  }, [clamped]);

  return (
    <div className="relative h-48 w-48">
      <svg viewBox="0 0 200 200" className="h-full w-full">
        <Ticks />
        <path
          d={arcPath(START_ANGLE, START_ANGLE + SWEEP, RADIUS)}
          fill="none"
          stroke="var(--color-line)"
          strokeWidth="7"
          strokeLinecap="round"
        />
        <path
          d={arcPath(START_ANGLE, START_ANGLE + SWEEP, RADIUS)}
          fill="none"
          stroke={stroke}
          strokeWidth="7"
          strokeLinecap="round"
          pathLength={100}
          strokeDasharray="100"
          strokeDashoffset={100 - shown}
          style={{
            transition: "stroke-dashoffset 0.9s cubic-bezier(0.22, 1, 0.36, 1)",
            filter: `drop-shadow(0 0 6px ${stroke}55)`,
          }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span
          className="font-display text-5xl font-semibold tabular-nums"
          style={{ color: stroke }}
        >
          {clamped}
        </span>
        <span className="micro-label mt-1 text-faint">{t("report.gaugeLabel")}</span>
      </div>
    </div>
  );
}
