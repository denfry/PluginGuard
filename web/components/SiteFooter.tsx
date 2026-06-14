"use client";

import { useI18n } from "@/lib/i18n";

export function SiteFooter() {
  const { t } = useI18n();
  return (
    <footer className="mt-24 border-t border-line">
      <div className="container-page flex flex-col gap-2 py-6 sm:flex-row sm:items-center sm:justify-between">
        <p className="text-xs text-muted">{t("footer.tagline")}</p>
        <p className="micro-label text-faint">{t("footer.meta")}</p>
      </div>
    </footer>
  );
}
