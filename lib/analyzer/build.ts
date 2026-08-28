import type JSZip from "jszip";

export type BuildTool = "Gradle" | "Maven" | "Unknown";
export type BuildIdentity = {
  sha256: string;
  tool: BuildTool;
  toolEvidence: string[];
  declaredVersion?: string;
  implementationVersion?: string;
  versionSource?: string;
  title?: string;
  implementationVendor?: string;
  artifact?: string;
  group?: string;
  commit?: string;
  buildJdk?: string;
  createdBy?: string;
  builtBy?: string;
  automaticModuleName?: string;
  languageSignals: string[];
  sources: string[];
};

type PropertySource = { path: string; values: Record<string, string> };

/** Creates a local fingerprint and reads Gradle, Maven, Git and manifest build metadata. */
export async function inspectBuild(zip: JSZip, archive: ArrayBuffer, declaredVersion?: string): Promise<BuildIdentity> {
  const paths = Object.keys(zip.files).filter((path) => !zip.files[path].dir);
  const manifest = parseManifest(await readText(zip, "META-INF/MANIFEST.MF"));
  const propertySources = await readBuildProperties(zip, paths);
  const sources = [Object.keys(manifest).length > 0 ? "META-INF/MANIFEST.MF" : undefined, ...propertySources.map((item) => item.path)].filter((item): item is string => Boolean(item));
  const implementationVersion = manifestValue(manifest, ["Implementation-Version", "Bundle-Version", "Specification-Version"]) || propertyValue(propertySources, ["version", "project.version", "build.version", "plugin.version"]);
  const tool = detectBuildTool(paths, manifest, propertySources);
  return {
    sha256: await digest(archive),
    tool: tool.name,
    toolEvidence: tool.evidence,
    declaredVersion,
    implementationVersion,
    versionSource: implementationVersion ? detectVersionSource(manifest, propertySources) : declaredVersion ? "plugin descriptor" : undefined,
    title: manifestValue(manifest, ["Implementation-Title", "Specification-Title", "Bundle-Name"]),
    implementationVendor: manifestValue(manifest, ["Implementation-Vendor", "Implementation-Vendor-Id", "Bundle-Vendor"]),
    artifact: propertyValue(propertySources, ["artifactId", "project.artifactId", "archivesBaseName", "rootProject.name", "name"]) || manifestValue(manifest, ["Implementation-Title"]),
    group: propertyValue(propertySources, ["groupId", "project.groupId", "group"]),
    commit: propertyValue(propertySources, ["git.commit.id.abbrev", "git.commit.id.full", "git.commit.id", "build.commit", "commit", "commitId"]) || manifestValue(manifest, ["Git-Commit", "Build-Commit", "Implementation-Commit"]),
    buildJdk: manifestValue(manifest, ["Build-Jdk-Spec", "Build-Jdk", "Build-Java-Version", "Jdk-Version"]),
    createdBy: manifestValue(manifest, ["Created-By", "Build-Tool"]),
    builtBy: manifestValue(manifest, ["Built-By", "Build-User"]),
    automaticModuleName: manifestValue(manifest, ["Automatic-Module-Name", "Bundle-SymbolicName"]),
    languageSignals: detectLanguages(paths),
    sources,
  };
}

function detectBuildTool(paths: string[], manifest: Record<string, string>, properties: PropertySource[]): { name: BuildTool; evidence: string[] } {
  const evidence: string[] = [];
  const createdBy = manifestValue(manifest, ["Created-By", "Build-Tool"]) || "";
  const hasGradle = /gradle/i.test(createdBy) || paths.some((path) => path.startsWith("META-INF/gradle-plugins/") || /(^|\/)gradle\.properties$/i.test(path)) || properties.some((item) => /gradle|build-info/i.test(item.path) && Object.keys(item.values).some((key) => /gradle/i.test(key)));
  const hasMaven = paths.some((path) => path.startsWith("META-INF/maven/") && /pom\.(properties|xml)$/i.test(path)) || /maven/i.test(createdBy);
  if (/gradle/i.test(createdBy)) evidence.push(createdBy);
  if (paths.some((path) => path.startsWith("META-INF/gradle-plugins/"))) evidence.push("Gradle plugin descriptor");
  if (hasMaven) evidence.push("Maven pom metadata");
  if (hasGradle) return { name: "Gradle", evidence: unique(evidence.length ? evidence : ["Gradle metadata pattern"]) };
  if (hasMaven) return { name: "Maven", evidence: unique(evidence) };
  return { name: "Unknown", evidence: [] };
}

async function readBuildProperties(zip: JSZip, paths: string[]): Promise<PropertySource[]> {
  const candidates = paths.filter((path) => /(^|\/)(pom|git|build-info|build|version|project|gradle)\.properties$/i.test(path) || path.startsWith("META-INF/gradle-plugins/")).slice(0, 16);
  return Promise.all(candidates.map(async (path) => ({ path, values: parseProperties(await readText(zip, path)) })));
}

function parseManifest(input: string) {
  const values: Record<string, string> = {};
  const unfolded: string[] = [];
  for (const raw of input.replace(/\r\n/g, "\n").split("\n")) {
    if (raw.startsWith(" ") && unfolded.length) unfolded[unfolded.length - 1] += raw.slice(1);
    else unfolded.push(raw);
  }
  for (const line of unfolded) { const divider = line.indexOf(":"); if (divider > 0) values[line.slice(0, divider).trim()] = line.slice(divider + 1).trim(); }
  return values;
}

function parseProperties(input: string) {
  const values: Record<string, string> = {};
  let current = "";
  for (const raw of input.replace(/\r\n/g, "\n").split("\n")) {
    current += raw;
    if (current.endsWith("\\")) { current = current.slice(0, -1); continue; }
    const line = current.trim(); current = "";
    if (!line || line.startsWith("#") || line.startsWith("!")) continue;
    const divider = line.search(/[=:]/);
    if (divider > 0) values[line.slice(0, divider).trim()] = line.slice(divider + 1).trim();
  }
  return values;
}

function detectVersionSource(manifest: Record<string, string>, properties: PropertySource[]) { if (manifestValue(manifest, ["Implementation-Version", "Bundle-Version", "Specification-Version"])) return "MANIFEST.MF"; return properties.find((item) => propertyValue([item], ["version", "project.version", "build.version", "plugin.version"]))?.path; }
function detectLanguages(paths: string[]) { const values: string[] = []; if (paths.some((path) => path.endsWith(".kotlin_module"))) values.push("Kotlin"); if (paths.some((path) => path.endsWith(".class"))) values.push("JVM bytecode"); if (paths.some((path) => path.startsWith("META-INF/versions/"))) values.push("Multi-release JAR"); return values; }
function manifestValue(values: Record<string, string>, keys: string[]) { for (const key of keys) { if (values[key]?.trim()) return values[key].trim(); } return undefined; }
function propertyValue(sources: PropertySource[], keys: string[]) { for (const source of sources) for (const key of keys) if (source.values[key]?.trim()) return source.values[key].trim(); return undefined; }
async function readText(zip: JSZip, path: string) { return zip.file(path) ? zip.file(path)!.async("text") : ""; }
async function digest(value: ArrayBuffer) { const hash = await crypto.subtle.digest("SHA-256", value); return Array.from(new Uint8Array(hash), (byte) => byte.toString(16).padStart(2, "0")).join(""); }
function unique(values: string[]) { return [...new Set(values)]; }
