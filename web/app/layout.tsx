import type { Metadata } from "next";
import { Geist, Geist_Mono, Space_Grotesk } from "next/font/google";
import "./globals.css";
import { Navbar } from "@/components/Navbar";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

const spaceGrotesk = Space_Grotesk({
  variable: "--font-space-grotesk",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "PluginGuard — Minecraft plugin security scanner",
  description:
    "Upload a Minecraft plugin .jar and get a deep static security report: bytecode analysis, suspicious behaviour, network indicators, obfuscation score and plugin.yml validation.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} ${spaceGrotesk.variable} h-full antialiased`}
    >
      <body className="min-h-full flex flex-col font-sans">
        <div className="bg-decor" aria-hidden />
        <Navbar />
        <main className="flex-1">{children}</main>
        <footer className="mt-24 border-t border-line">
          <div className="container-page flex flex-col gap-2 py-6 sm:flex-row sm:items-center sm:justify-between">
            <p className="text-xs text-muted">
              PluginGuard — risk-based static analysis. Not a guarantee of
              safety.
            </p>
            <p className="micro-label text-faint">
              static bytecode analysis · isolated sandbox
            </p>
          </div>
        </footer>
      </body>
    </html>
  );
}
