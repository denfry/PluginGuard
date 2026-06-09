import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
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
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="min-h-full flex flex-col font-sans">
        <Navbar />
        <main className="flex-1">{children}</main>
        <footer className="border-t border-line/60 mt-20">
          <div className="container-page py-8 text-sm text-muted flex flex-col sm:flex-row gap-2 sm:items-center sm:justify-between">
            <p>
              PluginGuard — risk-based static analysis. Not a guarantee of
              safety.
            </p>
            <p className="font-mono text-xs">static-analysis · no sandbox</p>
          </div>
        </footer>
      </body>
    </html>
  );
}
