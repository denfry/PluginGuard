"use client";

import { useEffect, useState } from "react";
import { scoreStroke } from "@/lib/format";

const CENTER = 100;
const RADIUS = 78;
const START_ANGLE = 135; // bottom-left, sweeping clockwise over the top
const SWEEP = 270;

function polar(angleDeg: number, radius: number): [number, number] {
  const a = (angleDeg * Math.PI) / 180;
  return [CENTER + radius * Math.cos(a), CENTER + radius * Math.sin(a)];
}

function arcPath(fromDeg: number, toDeg: number, radius: number): string {
  const [x1, y1] = polar(fromDeg, radius);
  const [x2, y2] = polar(toDeg, radius);
  const largeArc = toDeg - fromDeg > 180 ? 1 : 0;
  return `M ${x1.toFixed(2)} ${y1.toFixed(2)} A ${radius} ${radius} 0 ${largeArc} 1 ${x2.toFixed(2)} ${y2.toFixed(2)}`;
}

// Read-head dot at the zero position (the arc's leading edge); the group is
// rotated to the live value so the dot rides the arc as it fills. Quantized
// like arcPath() to keep the SSR and client SVG strings byte-identical and
// avoid a hydration mismatch.
const [HEAD_X, HEAD_Y] = polar(START_ANGLE, RADIUS);

/** Graduation ticks: a major line every 10 points, a minor one every 5. */
function Ticks() {
  const ticks = [];
  for (let value = 0; value <= 100; value += 5) {
    const angle = START_ANGLE + (value / 100) * SWEEP;
    const major = value % 10 === 0;
    const [x1, y1] = polar(angle, major ? 88 : 91);
    const [x2, y2] = polar(angle, 94);
    // Quantize like arcPath(): raw Math.cos/sin output can differ in the last
    // ULP between the SSR engine (Node) and the browser, mismatching the
    // serialized SVG attributes and tripping React hydration.
    ticks.push(
      <line
        key={value}
        x1={x1.toFixed(2)}
        y1={y1.toFixed(2)}
        x2={x2.toFixed(2)}
        y2={y2.toFixed(2)}
        stroke="currentColor"
        strokeWidth={major ? 1.5 : 1}
        className={major ? "text-line-strong" : "text-line"}
      />,
    );
  }
  return <>{ticks}</>;
}

export function ScoreGauge({ score, label = "safety / 100" }: { score: number; label?: string }) {
  const clamped = Math.max(0, Math.min(100, score));
  const stroke = scoreStroke(clamped);
  // Start at zero and let the arc + needle sweep up, and the number count up,
  // on mount. Initial state is 0 on both server and client to stay hydration-safe.
  const [shown, setShown] = useState(0);
  const [display, setDisplay] = useState(0);
  const [reduced, setReduced] = useState(false);

  useEffect(() => {
    const reduce =
      window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
    if (reduce) {
      // Defer into a frame so we never call setState synchronously in the effect body.
      const jump = requestAnimationFrame(() => {
        setReduced(true);
        setShown(clamped);
        setDisplay(clamped);
      });
      return () => cancelAnimationFrame(jump);
    }
    const arcFrame = requestAnimationFrame(() => setShown(clamped));

    let countFrame = 0;
    const start = performance.now();
    const duration = 900;
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - t, 3); // easeOutCubic
      setDisplay(Math.round(eased * clamped));
      if (t < 1) countFrame = requestAnimationFrame(tick);
    };
    countFrame = requestAnimationFrame(tick);

    return () => {
      cancelAnimationFrame(arcFrame);
      cancelAnimationFrame(countFrame);
    };
  }, [clamped]);

  const headAngle = (shown / 100) * SWEEP;

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
            transition: reduced
              ? "none"
              : "stroke-dashoffset 0.9s cubic-bezier(0.22, 1, 0.36, 1)",
            filter: `drop-shadow(0 0 6px ${stroke}55)`,
          }}
        />

        {/* Read-head dot riding the arc's leading edge to the live value. */}
        <g
          style={{
            transform: `rotate(${headAngle}deg)`,
            transformBox: "view-box",
            transformOrigin: "100px 100px",
            transition: reduced
              ? "none"
              : "transform 0.9s cubic-bezier(0.22, 1, 0.36, 1)",
          }}
        >
          <circle
            cx={HEAD_X.toFixed(2)}
            cy={HEAD_Y.toFixed(2)}
            r="3"
            fill="var(--color-bg)"
            stroke={stroke}
            strokeWidth="2"
            style={{ filter: `drop-shadow(0 0 6px ${stroke})` }}
          />
        </g>
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span
          className="font-display text-5xl font-semibold tabular-nums"
          style={{ color: stroke }}
        >
          {display}
        </span>
        <span className="micro-label mt-1 text-faint">{label}</span>
      </div>
    </div>
  );
}
