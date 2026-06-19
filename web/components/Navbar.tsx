"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ShieldIcon } from "./icons";

const LINKS: { href: string; label: string; desktopOnly?: boolean }[] = [
  { href: "/", label: "Scanner" },
  { href: "/demo", label: "Demo report" },
  // The anchor link is hidden on phones to keep the bar on one line.
  { href: "/#what-we-scan", label: "Pipeline", desktopOnly: true },
];

export function Navbar() {
  const pathname = usePathname();

  return (
    <header className="sticky top-0 z-30 border-b border-line bg-bg/85 backdrop-blur-md">
      <nav className="container-page flex h-14 items-center justify-between">
        <Link href="/" className="group flex items-center gap-2.5">
          <span className="text-primary transition-all duration-200 group-hover:scale-110 group-hover:drop-shadow-[0_0_8px_rgba(163,230,53,0.6)]">
            <ShieldIcon className="h-5 w-5" />
          </span>
          <span className="font-display text-base font-semibold tracking-tight">
            Plugin<span className="text-primary">Guard</span>
          </span>
        </Link>
        <div className="flex items-center gap-1">
          {LINKS.map((link) => {
            const active =
              link.href === "/#what-we-scan" ? false : pathname === link.href;
            return (
              <Link
                key={link.href}
                href={link.href}
                data-active={active}
                className={`nav-underline micro-label whitespace-nowrap rounded-md px-3 py-2 transition-colors ${
                  link.desktopOnly ? "hidden sm:block" : ""
                } ${
                  active ? "text-primary" : "text-muted hover:text-ink"
                }`}
              >
                {link.label}
              </Link>
            );
          })}
        </div>
      </nav>
    </header>
  );
}
