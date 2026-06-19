"use client";

import { useEffect, useRef, useState, type DragEvent } from "react";
import { useRouter } from "next/navigation";
import { ApiError, MAX_UPLOAD_BYTES, scanFile } from "@/lib/api";
import { formatBytes } from "@/lib/format";
import { UploadIcon, AlertIcon } from "./icons";

/** Plugins/mods are .jar; resource/data packs are .zip (.mcpack/.litemod also accepted). */
const ACCEPTED_EXTENSIONS = [".jar", ".zip", ".mcpack", ".litemod"];

/** Cycled under the progress readout so a running scan feels alive (flavor, not real progress). */
const SCAN_STAGES = [
  "structure",
  "bytecode",
  "network indicators",
  "dependencies",
  "obfuscation",
  "plugin.yml",
  "sandbox",
];

/** Viewfinder corner bracket; spreads outward while dragging a file over the zone. */
function Corner({ pos, out }: { pos: "tl" | "tr" | "bl" | "br"; out: boolean }) {
  const edges = {
    tl: "left-0 top-0 border-l-2 border-t-2 rounded-tl-md",
    tr: "right-0 top-0 border-r-2 border-t-2 rounded-tr-md",
    bl: "left-0 bottom-0 border-l-2 border-b-2 rounded-bl-md",
    br: "right-0 bottom-0 border-r-2 border-b-2 rounded-br-md",
  }[pos];
  const shift = {
    tl: "-translate-x-1.5 -translate-y-1.5",
    tr: "translate-x-1.5 -translate-y-1.5",
    bl: "-translate-x-1.5 translate-y-1.5",
    br: "translate-x-1.5 translate-y-1.5",
  }[pos];
  return (
    <span
      aria-hidden
      className={`pointer-events-none absolute z-10 h-5 w-5 border-primary transition-transform duration-300 ${edges} ${out ? shift : ""}`}
    />
  );
}

export function Dropzone() {
  const router = useRouter();
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const [busy, setBusy] = useState(false);
  const [fileLabel, setFileLabel] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [elapsed, setElapsed] = useState(0);
  const [stage, setStage] = useState(0);

  // Elapsed-time readout while the analyzer is working.
  useEffect(() => {
    if (!busy) return;
    const started = performance.now();
    const id = setInterval(
      () => setElapsed((performance.now() - started) / 1000),
      100,
    );
    return () => clearInterval(id);
  }, [busy]);

  // Cycle the stage label while scanning (reset happens in handleFile on start).
  useEffect(() => {
    if (!busy) return;
    const id = setInterval(
      () => setStage((s) => (s + 1) % SCAN_STAGES.length),
      700,
    );
    return () => clearInterval(id);
  }, [busy]);

  async function handleFile(file: File) {
    setError(null);
    if (!ACCEPTED_EXTENSIONS.some((ext) => file.name.toLowerCase().endsWith(ext))) {
      setError("Please choose a plugin/mod .jar or a resource/data pack .zip.");
      return;
    }
    if (file.size > MAX_UPLOAD_BYTES) {
      setError(`File is too large (${formatBytes(file.size)}). Max is 50 MB.`);
      return;
    }
    setElapsed(0);
    setStage(0);
    setBusy(true);
    setFileLabel(`${file.name} · ${formatBytes(file.size)}`);
    try {
      const result = await scanFile(file);
      router.push(`/report/${result.id}`);
    } catch (e) {
      setBusy(false);
      setFileLabel(null);
      setError(e instanceof ApiError ? e.message : "Analysis failed.");
    }
  }

  function onDrop(e: DragEvent<HTMLDivElement>) {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) void handleFile(file);
  }

  return (
    <div className="w-full">
      <div className="relative">
        <Corner pos="tl" out={dragging} />
        <Corner pos="tr" out={dragging} />
        <Corner pos="bl" out={dragging} />
        <Corner pos="br" out={dragging} />

        <div
          onDragOver={(e) => {
            e.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          onClick={() => !busy && inputRef.current?.click()}
          role="button"
          tabIndex={0}
          aria-busy={busy}
          onKeyDown={(e) => {
            if ((e.key === "Enter" || e.key === " ") && !busy)
              inputRef.current?.click();
          }}
          className={`group relative flex min-h-[19rem] cursor-pointer flex-col items-center justify-center gap-4 overflow-hidden rounded-xl border border-dashed px-6 py-12 text-center transition-colors duration-200
            ${
              dragging
                ? "border-primary/70 bg-primary/5"
                : "border-line-strong bg-card hover:border-primary/40"
            }
            ${busy ? "pointer-events-none" : ""}`}
        >
          <input
            ref={inputRef}
            type="file"
            accept=".jar,.zip,.mcpack,.litemod,application/java-archive,application/zip"
            className="hidden"
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) void handleFile(file);
              e.target.value = "";
            }}
          />

          {busy ? (
            <>
              <span
                aria-hidden
                className="animate-scan h-px bg-gradient-to-r from-transparent via-primary to-transparent shadow-[0_0_12px_2px_rgba(163,230,53,0.5)]"
              />
              <span className="font-mono text-sm text-ink">{fileLabel}</span>
              <p className="font-display text-lg font-medium">
                Scanning <span className="text-primary">{SCAN_STAGES[stage]}</span>
                …
              </p>
              <span className="font-mono text-xs text-primary tabular-nums">
                t+{elapsed.toFixed(1)}s
              </span>
            </>
          ) : (
            <>
              <span className="relative flex h-14 w-14 items-center justify-center">
                <span
                  aria-hidden
                  className="reticle-ping absolute inset-0 rounded-full border border-primary/40"
                />
                <span
                  aria-hidden
                  className="reticle-ping absolute inset-0 rounded-full border border-primary/30"
                  style={{ animationDelay: "1.3s" }}
                />
                <span className="relative flex h-14 w-14 items-center justify-center rounded-full border border-primary/30 bg-primary/10 text-primary transition-transform duration-300 group-hover:scale-110">
                  <UploadIcon className="h-6 w-6" />
                </span>
              </span>
              <div>
                <p className="font-display text-xl font-medium">
                  Drop a <span className="text-primary">.jar</span> or{" "}
                  <span className="text-primary">.zip</span> to scan it
                </p>
                <p className="mt-1.5 text-sm text-muted">
                  plugin · mod · resource / data pack · up to 50 MB
                </p>
              </div>
              <span className="btn-primary inline-flex items-center justify-center rounded-lg px-5 py-2.5 text-sm">
                Choose file
              </span>
            </>
          )}
        </div>
      </div>

      {error && (
        <div className="mt-4 flex items-start gap-2.5 rounded-lg border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-danger">
          <AlertIcon className="h-5 w-5 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <p className="micro-label mt-4 text-center text-faint">
        analyzed in isolation — nothing runs on your server
      </p>
    </div>
  );
}
