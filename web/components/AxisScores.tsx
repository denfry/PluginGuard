import type { AxisScore } from "@/lib/types";
import { AXIS_LABEL, verdictColor, scoreStroke } from "@/lib/format";

/**
 * The five scoring axes as a row of compact meters. Each reads like a gauge on a
 * rack: a label, the value in its band colour, a thin fill bar, and a one-line
 * reason. Sits directly on the page background, so it uses the --panel surface.
 */
export function AxisScores({ axes }: { axes: AxisScore[] }) {
  if (!axes || axes.length === 0) return null;
  return (
    <section className="reveal" aria-label="Per-axis scores" style={{ animationDelay: "0.1s" }}>
      <p className="micro-label mb-2.5 text-faint">{"//"} scoring axes</p>
      <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 lg:grid-cols-5">
        {axes.map((a) => {
          const color = scoreStroke(a.score);
          return (
            <div
              key={a.axis}
              className="hover-lift flex flex-col gap-2 rounded-lg border border-line bg-panel p-3.5"
            >
              <div className="flex items-center justify-between gap-2">
                <span className="micro-label truncate text-muted">
                  {AXIS_LABEL[a.axis]}
                </span>
                <span
                  className="font-display text-xl font-semibold tabular-nums leading-none"
                  style={{ color }}
                >
                  {a.score}
                </span>
              </div>
              <div className="h-1 w-full overflow-hidden rounded-full bg-line">
                <div
                  className="h-full rounded-full"
                  style={{ width: `${a.score}%`, backgroundColor: color }}
                />
              </div>
              <div className="flex items-baseline justify-between gap-2">
                <span className="line-clamp-2 text-[11px] leading-snug text-muted">
                  {a.headline}
                </span>
              </div>
              <span
                className={`micro-label mt-auto text-[10px] ${verdictColor(a.verdict)}`}
              >
                {a.verdict.replace(/_/g, " ")}
              </span>
            </div>
          );
        })}
      </div>
    </section>
  );
}
