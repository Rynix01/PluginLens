"use client";

import { useCallback, useRef, useState } from "react";
import { analyzePluginJar, type AnalysisResult } from "@/lib/analyzer";
import { Dropzone } from "@/components/dropzone";
import { Overview } from "@/components/overview";

export default function Home() {
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const inspect = useCallback(async (file: File) => {
    setError(null);
    setResult(null);
    if (!file.name.toLowerCase().endsWith(".jar")) {
      setError("Choose a Minecraft plugin JAR file (.jar).");
      return;
    }
    setIsAnalyzing(true);
    try {
      setResult(await analyzePluginJar(file));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "The JAR could not be read.");
    } finally {
      setIsAnalyzing(false);
    }
  }, []);

  return (
    <main className="min-h-screen px-5 py-8 sm:px-8 lg:px-12">
      <header className="mx-auto flex max-w-6xl items-center justify-between border-b border-slate-800 pb-6">
        <div className="flex items-center gap-3"><span className="grid h-9 w-9 place-items-center rounded-lg bg-cyan-400 font-black text-slate-950">PL</span><div><h1 className="font-mono text-lg font-bold tracking-tight text-white">PluginLens</h1><p className="text-xs text-slate-500">Minecraft plugin inspector</p></div></div>
        <div className="hidden items-center gap-2 rounded-full border border-emerald-900/70 bg-emerald-950/30 px-3 py-1.5 text-xs text-emerald-300 sm:flex"><span className="h-1.5 w-1.5 rounded-full bg-emerald-400" /> Local-only analysis</div>
      </header>

      <section className="mx-auto max-w-6xl py-14 lg:py-20">
        {!result ? <><div className="mb-10 max-w-2xl"><p className="mb-3 font-mono text-sm text-cyan-300">// inspect without uploading</p><h2 className="text-4xl font-semibold tracking-tight text-white sm:text-5xl">Understand a plugin<br /><span className="text-slate-500">before it reaches your server.</span></h2><p className="mt-5 max-w-xl text-base leading-7 text-slate-400">Read manifest metadata and JAR structure directly in your browser. Your plugin never leaves this device.</p></div><Dropzone onFile={inspect} busy={isAnalyzing} inputRef={inputRef} /><p className="mt-4 text-center text-xs text-slate-600">No accounts. No uploads. No server-side analysis.</p>{error && <p role="alert" className="mx-auto mt-5 max-w-2xl rounded-lg border border-rose-900/70 bg-rose-950/30 px-4 py-3 text-sm text-rose-200">{error}</p>}</> : <Overview result={result} onReset={() => { setResult(null); setError(null); }} />}
      </section>
    </main>
  );
}
