import type { ReactNode } from "react";

export function Panel({
  title,
  icon,
  action,
  children,
  className = "",
  delay,
}: {
  title?: string;
  icon?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
  /** When set, the panel does a one-shot entrance reveal with this delay (seconds). */
  delay?: number;
}) {
  return (
    <section
      className={`rounded-xl border border-line bg-card transition-colors duration-200 hover:border-line-strong ${
        delay !== undefined ? "reveal" : ""
      } ${className}`}
      style={delay !== undefined ? { animationDelay: `${delay}s` } : undefined}
    >
      {title && (
        <header className="flex items-center justify-between gap-3 border-b border-line px-5 py-3">
          <h2 className="micro-label flex items-center gap-2 text-muted">
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
