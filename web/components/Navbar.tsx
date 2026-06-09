import Link from "next/link";
import { ShieldIcon } from "./icons";

export function Navbar() {
  return (
    <header className="sticky top-0 z-30 border-b border-line/60 bg-bg/80 backdrop-blur">
      <nav className="container-page flex h-16 items-center justify-between">
        <Link href="/" className="flex items-center gap-2.5 group">
          <span className="text-primary transition-transform group-hover:scale-110">
            <ShieldIcon className="h-6 w-6" />
          </span>
          <span className="text-lg font-semibold tracking-tight">
            Plugin<span className="text-primary">Guard</span>
          </span>
        </Link>
        <div className="flex items-center gap-1 text-sm">
          <Link
            href="/"
            className="px-3 py-2 rounded-md text-muted hover:text-ink hover:bg-card/60 transition"
          >
            Scanner
          </Link>
          <Link
            href="/demo"
            className="px-3 py-2 rounded-md text-muted hover:text-ink hover:bg-card/60 transition"
          >
            Demo report
          </Link>
          <Link
            href="/#what-we-scan"
            className="px-3 py-2 rounded-md text-muted hover:text-ink hover:bg-card/60 transition"
          >
            What we scan
          </Link>
        </div>
      </nav>
    </header>
  );
}
