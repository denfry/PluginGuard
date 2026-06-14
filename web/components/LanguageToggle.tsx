"use client";

import { useI18n, type Lang } from "@/lib/i18n";
import { GlobeIcon } from "./icons";

const LANGS: Lang[] = ["en", "ru"];

/** Compact EN / RU segmented switch wired to the i18n context. */
export function LanguageToggle() {
  const { lang, setLang, t } = useI18n();

  return (
    <div
      role="group"
      aria-label={t("nav.language")}
      className="flex items-center gap-1 rounded-md border border-line bg-card/60 px-1 py-0.5"
    >
      <GlobeIcon className="mx-1 h-3.5 w-3.5 text-faint" />
      {LANGS.map((code) => {
        const active = lang === code;
        return (
          <button
            key={code}
            onClick={() => setLang(code)}
            aria-pressed={active}
            className={`rounded px-1.5 py-0.5 font-mono text-[11px] font-medium uppercase tracking-[0.1em] transition-colors ${
              active
                ? "bg-primary/15 text-primary"
                : "text-muted hover:text-ink"
            }`}
          >
            {code}
          </button>
        );
      })}
    </div>
  );
}
