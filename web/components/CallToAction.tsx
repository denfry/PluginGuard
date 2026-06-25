import Link from "next/link";
import { ArrowRightIcon } from "./icons";

/** Closing band: send the reader back to the one action that matters — scanning. */
export function CallToAction() {
  return (
    <div className="relative overflow-hidden rounded-xl border border-line bg-card px-6 py-12 text-center lg:py-16">
      {/* Faint phosphor wash to set the closing band apart from the panels above. */}
      <span
        aria-hidden
        className="pointer-events-none absolute inset-0"
        style={{
          backgroundImage:
            "radial-gradient(40rem 18rem at 50% 120%, rgb(163 230 53 / 0.08), transparent 70%)",
        }}
      />
      <div className="relative">
        <p className="micro-label text-primary">{"//"} ready when you are</p>
        <h2 className="mx-auto mt-3 max-w-xl font-display text-3xl font-semibold tracking-tight">
          Know before you{" "}
          <span className="text-primary text-glow">deploy</span>.
        </h2>
        <p className="mx-auto mt-3 max-w-md text-muted">
          Drag in a build and read its report in seconds. No account, no install.
        </p>
        <Link
          href="/#top"
          className="btn-primary group mt-7 inline-flex items-center gap-2 rounded-lg px-6 py-3 text-sm"
        >
          Scan a plugin
          <ArrowRightIcon className="h-4 w-4 transition-transform duration-200 group-hover:translate-x-0.5" />
        </Link>
      </div>
    </div>
  );
}
