import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "PluginLens — Local Minecraft plugin inspection",
  description: "Inspect Minecraft plugin JARs locally in your browser.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
