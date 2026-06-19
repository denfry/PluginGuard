import type { AxisScore } from "@/lib/types";
import { AXIS_LABEL, verdictColor, scoreStroke } from "@/lib/format";

/** Compact horizontal strip of per-axis meters shown beside the main gauge. */
export function AxisScores({ axes }: { axes: AxisScore[] }) {
  if (!axes || axes.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-3">
      {axes.map((a) => (
        <div
          key={a.axis}
          className="flex min-w-[9rem] flex-1 flex-col gap-1 rounded-md border border-line bg-panel/40 p-3"
        >
          <span className="micro-label text-faint">{AXIS_LABEL[a.axis]}</span>
          <div className="flex items-baseline justify-between">
            <span
              className="font-display text-2xl font-semibold tabular-nums"
              style={{ color: scoreStroke(a.score) }}
            >
              {a.score}
            </span>
            <span className={`text-xs ${verdictColor(a.verdict)}`}>{a.verdict.replace("_", " ")}</span>
          </div>
          <div className="h-1 w-full overflow-hidden rounded-full bg-line">
            <div
              className="h-full rounded-full"
              style={{ width: `${a.score}%`, backgroundColor: scoreStroke(a.score) }}
            />
          </div>
          <span className="text-[11px] text-muted">{a.headline}</span>
        </div>
      ))}
    </div>
  );
}
