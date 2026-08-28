"use client";

import { useState } from "react";
import type { BuildIdentity } from "@/lib/analyzer/build";
import { githubRepository, type SourceIdentity } from "@/lib/analyzer/source";

type GithubAsset = { name: string; digest: string | null; browser_download_url: string };
type GithubRelease = { tag_name: string; html_url: string; assets: GithubAsset[] };
type Verification = { state: "verified" | "mismatch" | "release-found" | "not-found" | "error"; message: string; releaseUrl?: string; asset?: string };

export function ReleaseVerification({ source, build }: { source: SourceIdentity; build: BuildIdentity }) {
  const [repositoryUrl, setRepositoryUrl] = useState(source.repository?.url || "");
  const [checking, setChecking] = useState(false);
  const [verification, setVerification] = useState<Verification | null>(null);

  async function verify() {
    const repository = githubRepository(repositoryUrl);
    if (!repository) { setVerification({ state: "error", message: "Enter a valid public GitHub repository URL." }); return; }
    if (!source.tagCandidates.length) { setVerification({ state: "error", message: "No plugin version was detected, so a release tag cannot be selected safely." }); return; }
    setChecking(true); setVerification(null);
    try {
      let release: GithubRelease | undefined;
      for (const tag of source.tagCandidates) {
        const response = await fetch(`https://api.github.com/repos/${repository.owner}/${repository.repo}/releases/tags/${encodeURIComponent(tag)}`, { headers: { Accept: "application/vnd.github+json" } });
        if (response.ok) { release = await response.json() as GithubRelease; break; }
        if (response.status !== 404) throw new Error(response.status === 403 ? "GitHub API rate limit reached. Try again later." : `GitHub returned HTTP ${response.status}.`);
      }
      if (!release) { setVerification({ state: "not-found", message: `No release matched ${source.tagCandidates.join(", ")}.` }); return; }
      const jars = release.assets.filter((asset) => asset.name.toLowerCase().endsWith(".jar"));
      const digested = jars.filter((asset) => asset.digest?.toLowerCase().startsWith("sha256:"));
      const match = digested.find((asset) => asset.digest!.slice(7).toLowerCase() === build.sha256.toLowerCase());
      if (match) setVerification({ state: "verified", message: `Byte-for-byte match with ${match.name} from release ${release.tag_name}.`, releaseUrl: release.html_url, asset: match.name });
      else if (digested.length) setVerification({ state: "mismatch", message: `Release ${release.tag_name} has ${digested.length} JAR digest(s), but none match this file.`, releaseUrl: release.html_url });
      else setVerification({ state: "release-found", message: `Release ${release.tag_name} was found, but GitHub does not publish a SHA-256 digest for its JAR asset.`, releaseUrl: release.html_url });
    } catch (cause) { setVerification({ state: "error", message: cause instanceof Error ? cause.message : "Release verification failed." }); }
    finally { setChecking(false); }
  }

  return <section className="rounded-xl border border-slate-800 bg-slate-900/70 p-5"><div className="flex flex-wrap items-end justify-between gap-3"><div><p className="font-mono text-xs text-slate-500">SOURCE & RELEASE</p><h3 className="mt-1 text-lg font-medium text-white">Official binary verification</h3></div><span className="rounded-full bg-emerald-400/10 px-2.5 py-1 text-xs text-emerald-300">JAR never uploaded</span></div><p className="mt-3 max-w-3xl text-sm leading-6 text-slate-500">PluginLens queries public GitHub release metadata from your browser and compares GitHub’s published digest with the local SHA-256.</p><div className="mt-5 flex flex-col gap-3 sm:flex-row"><input value={repositoryUrl} onChange={(event) => { setRepositoryUrl(event.target.value); setVerification(null); }} placeholder="https://github.com/owner/repository" className="min-w-0 flex-1 rounded-lg border border-slate-700 bg-slate-950 px-4 py-2.5 font-mono text-sm text-slate-200 outline-none focus:border-cyan-400" /><button onClick={verify} disabled={checking} className="rounded-lg bg-cyan-400 px-4 py-2.5 text-sm font-semibold text-slate-950 hover:bg-cyan-300 disabled:cursor-wait disabled:opacity-60">{checking ? "Checking GitHub…" : "Verify official release"}</button></div>{source.repository && <p className="mt-2 text-xs text-slate-600">Detected from {source.evidence.join(", ")} · tags: {source.tagCandidates.join(", ") || "none"}</p>}{verification && <div className={`mt-4 rounded-lg border px-4 py-3 text-sm ${verificationStyle(verification.state)}`}><p>{verification.message}</p>{verification.releaseUrl && <a href={verification.releaseUrl} target="_blank" rel="noreferrer" className="mt-2 inline-block text-xs underline underline-offset-4">Open GitHub release ↗</a>}</div>}</section>;
}

function verificationStyle(state: Verification["state"]) { return ({ verified: "border-emerald-800 bg-emerald-950/30 text-emerald-200", mismatch: "border-rose-800 bg-rose-950/30 text-rose-200", "release-found": "border-amber-800 bg-amber-950/30 text-amber-200", "not-found": "border-slate-700 bg-slate-950/50 text-slate-300", error: "border-rose-900 bg-rose-950/20 text-rose-200" })[state]; }
