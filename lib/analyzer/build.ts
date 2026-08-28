import type JSZip from "jszip";

export type BuildIdentity = { sha256: string; implementationVersion?: string; implementationVendor?: string; artifact?: string; group?: string; commit?: string; sources: string[] };

/** Creates a local fingerprint and reads common embedded build metadata. No network requests are made. */
export async function inspectBuild(zip: JSZip, archive: ArrayBuffer): Promise<BuildIdentity> {
  const sha256 = await digest(archive);
  const manifest = await readProperties(zip, "META-INF/MANIFEST.MF");
  const properties = await firstProperties(zip, ["META-INF/maven/", "git.properties", "build-info.properties"]);
  const sources = [zip.file("META-INF/MANIFEST.MF") && "MANIFEST.MF", ...properties.sources].filter((item): item is string => Boolean(item));
  return {
    sha256,
    implementationVersion: value(manifest, "Implementation-Version") || value(properties.values, "version") || value(properties.values, "project.version"),
    implementationVendor: value(manifest, "Implementation-Vendor"),
    artifact: value(properties.values, "artifactId") || value(properties.values, "project.artifactId"),
    group: value(properties.values, "groupId") || value(properties.values, "project.groupId"),
    commit: value(properties.values, "git.commit.id.abbrev") || value(properties.values, "git.commit.id") || value(properties.values, "build.commit"),
    sources,
  };
}

async function digest(value: ArrayBuffer) { const hash = await crypto.subtle.digest("SHA-256", value); return Array.from(new Uint8Array(hash), (byte) => byte.toString(16).padStart(2, "0")).join(""); }
async function firstProperties(zip: JSZip, candidates: string[]) { const paths = Object.keys(zip.files).filter((path) => candidates.some((candidate) => candidate.endsWith("/") ? path.startsWith(candidate) && path.endsWith(".properties") : path.endsWith(candidate))); const results = await Promise.all(paths.slice(0, 4).map(async (path) => ({ path, values: await readProperties(zip, path) })));
  return { values: Object.assign({}, ...results.map((result) => result.values)), sources: results.map((result) => result.path) };
}
async function readProperties(zip: JSZip, path: string) { const entry = zip.file(path); if (!entry) return {} as Record<string, string>; return parseProperties(await entry.async("text")); }
function parseProperties(input: string) { const values: Record<string, string> = {}; let current = ""; for (const raw of input.replace(/\r\n/g, "\n").split("\n")) { current += raw; if (current.endsWith("\\")) { current = current.slice(0, -1); continue; } const line = current.trim(); current = ""; if (!line || line.startsWith("#") || line.startsWith("!")) continue; const divider = line.search(/[=:]/); if (divider > 0) values[line.slice(0, divider).trim()] = line.slice(divider + 1).trim(); } return values; }
function value(values: Record<string, string>, key: string) { return values[key]?.trim() || undefined; }
