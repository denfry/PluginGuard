import type { ReactNode } from "react";

export function Panel({
  title,
  icon,
  action,
  children,
  className = "",
}: {
  title?: string;
  icon?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section
      className={`rounded-2xl border border-line bg-card/50 ${className}`}
    >
      {title && (
        <header className="flex items-center justify-between gap-3 border-b border-line/60 px-5 py-3.5">
          <h2 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-muted">
            {icon && <span className="text-primary">{icon}</span>}
            {title}
          </h2>
          {action}
        </header>
      )}
      <div className="p-5">{children}</div>
    </section>
  );
}
