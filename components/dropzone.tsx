import type { RefObject } from "react";
import { useState } from "react";

type DropzoneProps = { onFile: (file: File) => void; busy: boolean; inputRef: RefObject<HTMLInputElement | null> };

export function Dropzone({ onFile, busy, inputRef }: DropzoneProps) {
  const [dragging, setDragging] = useState(false);
  return <div onDragOver={(event) => { event.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={(event) => { event.preventDefault(); setDragging(false); const file = event.dataTransfer.files[0]; if (file) onFile(file); }} className={`relative grid min-h-72 place-items-center rounded-2xl border border-dashed p-8 transition ${dragging ? "border-cyan-400 bg-cyan-400/10" : "border-slate-700 bg-slate-900/60 hover:border-slate-500"}`}>
    <input ref={inputRef} className="hidden" type="file" accept=".jar,application/java-archive" onChange={(event) => { const file = event.target.files?.[0]; if (file) onFile(file); event.currentTarget.value = ""; }} />
    <div className="text-center"><div className="mx-auto mb-5 grid h-14 w-14 place-items-center rounded-xl border border-cyan-400/30 bg-cyan-400/10 font-mono text-2xl text-cyan-300">▣</div><h3 className="text-lg font-medium text-white">{busy ? "Inspecting plugin…" : "Drop a plugin JAR here"}</h3><p className="mt-2 text-sm text-slate-500">{busy ? "Parsing classes, calls, metadata and fingerprints" : "or browse from your computer · max 128 MB"}</p><button disabled={busy} onClick={() => inputRef.current?.click()} className="mt-6 rounded-lg bg-cyan-400 px-4 py-2 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300 disabled:cursor-wait disabled:opacity-60">{busy ? "Analyzing" : "Choose .jar file"}</button></div>
  </div>;
}
