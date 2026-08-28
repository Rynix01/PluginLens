import type JSZip from "jszip";

export type SourceRepository = { provider: "github"; owner: string; repo: string; url: string };
export type SourceIdentity = { repository?: SourceRepository; evidence: string[]; version?: string; tagCandidates: string[] };

/** Discovers source repository hints embedded in descriptors, manifests, Git metadata, or Maven POMs. */
export async function inspectSource(zip: JSZip, website?: string, version?: string): Promise<SourceIdentity> {
  const candidates: Array<{ value?: string; source: string }> = [{ value: website, source: "plugin descriptor website" }];
  const manifest = parseManifest(await text(zip, "META-INF/MANIFEST.MF"));
  for (const key of ["Implementation-URL", "Project-URL", "Scm-URL", "Build-Scm-Url", "Git-Repository"]) candidates.push({ value: manifest[key], source: `MANIFEST.MF ${key}` });
  for (const path of Object.keys(zip.files).filter((entry) => /(^|\/)(git|build-info)\.properties$/i.test(entry)).slice(0, 8)) {
    const properties = parseProperties(await text(zip, path));
    for (const key of ["git.remote.origin.url", "remote.origin.url", "git.repository", "scm.url"]) candidates.push({ value: properties[key], source: `${path} ${key}` });
  }
  for (const path of Object.keys(zip.files).filter((entry) => /(^|\/)pom\.xml$/i.test(entry)).slice(0, 4)) {
    const pom = await text(zip, path);
    for (const value of xmlUrls(pom)) candidates.push({ value, source: path });
  }
  for (const candidate of candidates) {
    const repository = githubRepository(candidate.value);
    if (repository) return { repository, evidence: [candidate.source], version, tagCandidates: tags(version) };
  }
  return { evidence: [], version, tagCandidates: tags(version) };
}

export function githubRepository(input?: string): SourceRepository | undefined {
  if (!input) return undefined;
  const normalized = input.trim().replace(/^scm:git:/i, "").replace(/^git\+/, "").replace(/^git@github\.com:/i, "https://github.com/");
  const match = normalized.match(/github\.com[/:]([^/\s]+)\/([^/#\s]+)/i);
  if (!match) return undefined;
  const owner = match[1];
  const repo = match[2].replace(/\.git$/i, "");
  return { provider: "github", owner, repo, url: `https://github.com/${owner}/${repo}` };
}

function tags(version?: string) { if (!version) return []; const clean = version.trim(); const withoutV = clean.replace(/^v/i, ""); return [...new Set([clean, `v${withoutV}`, withoutV, `release-${withoutV}`])]; }
function xmlUrls(input: string) { const values: string[] = []; const patterns = [/<scm>[\s\S]*?<url>([^<]+)<\/url>[\s\S]*?<\/scm>/gi, /<connection>([^<]+)<\/connection>/gi, /<developerConnection>([^<]+)<\/developerConnection>/gi, /<url>(https?:\/\/github\.com\/[^<]+)<\/url>/gi]; for (const pattern of patterns) { let match: RegExpExecArray | null; while ((match = pattern.exec(input))) values.push(decodeXml(match[1].trim())); } return values; }
function decodeXml(value: string) { return value.replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">"); }
function parseManifest(input: string) { const values: Record<string, string> = {}; const unfolded: string[] = []; for (const raw of input.replace(/\r\n/g, "\n").split("\n")) { if (raw.startsWith(" ") && unfolded.length) unfolded[unfolded.length - 1] += raw.slice(1); else unfolded.push(raw); } for (const line of unfolded) { const divider = line.indexOf(":"); if (divider > 0) values[line.slice(0, divider).trim()] = line.slice(divider + 1).trim(); } return values; }
function parseProperties(input: string) { const values: Record<string, string> = {}; for (const raw of input.replace(/\r\n/g, "\n").split("\n")) { const line = raw.trim(); if (!line || line.startsWith("#") || line.startsWith("!")) continue; const divider = line.search(/[=:]/); if (divider > 0) values[line.slice(0, divider).trim()] = line.slice(divider + 1).trim(); } return values; }
async function text(zip: JSZip, path: string) { return zip.file(path) ? zip.file(path)!.async("text") : ""; }
