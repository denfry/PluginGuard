"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ShieldIcon } from "./icons";
import { LanguageToggle } from "./LanguageToggle";
import { useI18n } from "@/lib/i18n";

const LINKS: { href: string; key: string; desktopOnly?: boolean }[] = [
  { href: "/", key: "nav.scanner" },
  { href: "/demo", key: "nav.demo" },
  // The anchor link is hidden on phones to keep the bar on one line.
  { href: "/#what-we-scan", key: "nav.pipeline", desktopOnly: true },
];

export function Navbar() {
  const pathname = usePathname();
  const { t } = useI18n();

  return (
    <header className="sticky top-0 z-30 border-b border-line bg-bg/85 backdrop-blur-md">
      <nav className="container-page flex h-14 items-center justify-between">
        <Link href="/" className="group flex items-center gap-2.5">
          <span className="text-primary transition-transform duration-200 group-hover:scale-110">
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
                className={`micro-label whitespace-nowrap rounded-md px-3 py-2 transition-colors ${
                  link.desktopOnly ? "hidden sm:block" : ""
                } ${
                  active
                    ? "text-primary"
                    : "text-muted hover:bg-card hover:text-ink"
                }`}
              >
                {t(link.key)}
              </Link>
            );
          })}
          <span className="ml-1.5">
            <LanguageToggle />
          </span>
        </div>
      </nav>
    </header>
  );
}
