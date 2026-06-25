import type { ReactNode } from "react";

/** The recurring section voice: a phosphor eyebrow, a display title, an optional aside. */
export function SectionHeading({
  eyebrow,
  title,
  aside,
}: {
  eyebrow: string;
  title: ReactNode;
  aside?: ReactNode;
}) {
  return (
    <div className="mb-8 flex items-end justify-between gap-6">
      <div>
        <p className="micro-label text-primary">
          {"//"} {eyebrow}
        </p>
        <h2 className="mt-2 font-display text-3xl font-semibold tracking-tight">
          {title}
        </h2>
      </div>
      {aside && (
        <p className="hidden max-w-xs text-right text-sm text-muted sm:block">
          {aside}
        </p>
      )}
    </div>
  );
}
