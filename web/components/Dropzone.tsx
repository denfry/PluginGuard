"use client";

import { useRef, useState, type DragEvent } from "react";
import { useRouter } from "next/navigation";
import { ApiError, MAX_UPLOAD_BYTES, scanFile } from "@/lib/api";
import { formatBytes } from "@/lib/format";
import { UploadIcon, AlertIcon } from "./icons";

export function Dropzone() {
  const router = useRouter();
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleFile(file: File) {
    setError(null);
    if (!file.name.toLowerCase().endsWith(".jar")) {
      setError("Please choose a .jar file.");
      return;
    }
    if (file.size > MAX_UPLOAD_BYTES) {
      setError(`File is too large (${formatBytes(file.size)}). Max is 50 MB.`);
      return;
    }
    setBusy(true);
    setStatus(`Analyzing ${file.name} (${formatBytes(file.size)})…`);
    try {
      const result = await scanFile(file);
      router.push(`/report/${result.id}`);
    } catch (e) {
      setBusy(false);
      setStatus(null);
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
        onKeyDown={(e) => {
          if ((e.key === "Enter" || e.key === " ") && !busy)
            inputRef.current?.click();
        }}
        className={`relative flex flex-col items-center justify-center gap-4 rounded-2xl border-2 border-dashed px-6 py-14 text-center transition cursor-pointer
          ${
            dragging
              ? "border-primary bg-primary/5"
              : "border-line hover:border-primary/60 bg-card/40"
          }
          ${busy ? "pointer-events-none opacity-80" : ""}`}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".jar,application/java-archive"
          className="hidden"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) void handleFile(file);
            e.target.value = "";
          }}
        />

        {busy ? (
          <>
            <span className="h-10 w-10 rounded-full border-2 border-primary/30 border-t-primary animate-spin" />
            <p className="text-ink font-medium">{status}</p>
            <p className="text-sm text-muted">Running static analysis…</p>
          </>
        ) : (
          <>
            <span className="text-primary">
              <UploadIcon className="h-10 w-10" />
            </span>
            <div>
              <p className="text-lg font-medium text-ink">
                Drag &amp; drop your{" "}
                <span className="font-mono text-primary">.jar</span> plugin here
              </p>
              <p className="text-sm text-muted mt-1">
                or click to choose a file · max 50 MB
              </p>
            </div>
            <span className="rounded-lg bg-primary px-4 py-2 text-sm font-medium text-bg hover:bg-primary/90 transition">
              Choose file
            </span>
          </>
        )}
      </div>

      {error && (
        <div className="mt-4 flex items-start gap-2 rounded-lg border border-danger/40 bg-danger/10 px-4 py-3 text-sm text-danger">
          <AlertIcon className="h-5 w-5 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <p className="mt-4 text-center text-xs text-muted">
        Your file is analyzed statically and never executed.
      </p>
    </div>
  );
}
