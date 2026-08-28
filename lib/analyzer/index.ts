import JSZip from "jszip";
import { inspectBuild, type BuildIdentity } from "./build";
import { buildInventory, parseClassFiles, type ClassInventory } from "./class-parser";
import { parsePluginMetadata, type PluginMetadata } from "./metadata";
import { scanSecurity, type SecurityReport } from "./security";
import { inspectSource, type SourceIdentity } from "./source";

export const MAX_JAR_SIZE = 128 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES = 100_000;
const MAX_CLASS_FILES = 50_000;
export type ArchiveReport = { entryCount: number; classCount: number; resourceCount: number; embeddedJarCount: number; nativeLibraryCount: number; serviceProviderCount: number; signed: boolean };
export type AnalysisResult = { schemaVersion: 1; analyzedAt: string; file: { name: string; size: number }; metadata: PluginMetadata; archive: ArchiveReport; classes: ClassInventory; security: SecurityReport; build: BuildIdentity; source: SourceIdentity };

/** Browser-only orchestrator. Future scanners receive this local ZIP model, never an uploaded file. */
export async function analyzePluginJar(file: File): Promise<AnalysisResult> {
  if (file.size > MAX_JAR_SIZE) throw new Error("This JAR exceeds the 128 MB local-analysis limit.");
  let zip: JSZip;
  const bytes = await file.arrayBuffer();
  try { zip = await JSZip.loadAsync(bytes); } catch { throw new Error("This file is not a readable JAR/ZIP archive."); }
  const paths = Object.keys(zip.files).filter((path) => !zip.files[path].dir);
  if (paths.length > MAX_ARCHIVE_ENTRIES) throw new Error("This archive contains more than 100,000 entries and was stopped for browser safety.");
  if (paths.filter((path) => path.endsWith(".class")).length > MAX_CLASS_FILES) throw new Error("This archive contains more than 50,000 classes and was stopped for browser safety.");
  const metadata = await parsePluginMetadata(zip);
  const parsedClasses = await parseClassFiles(zip);
  const security = scanSecurity(parsedClasses, paths, metadata.main);
  const build = await inspectBuild(zip, bytes, metadata.version);
  const source = await inspectSource(zip, metadata.website, metadata.version || build.implementationVersion, { pluginName: metadata.name, artifact: build.artifact, mainClass: metadata.main });
  const archive: ArchiveReport = { entryCount: paths.length, classCount: paths.filter((path) => path.endsWith(".class")).length, resourceCount: paths.filter((path) => !path.endsWith(".class")).length, embeddedJarCount: paths.filter((path) => path.toLowerCase().endsWith(".jar")).length, nativeLibraryCount: paths.filter((path) => /\.(dll|so|dylib)$/i.test(path)).length, serviceProviderCount: paths.filter((path) => path.startsWith("META-INF/services/")).length, signed: paths.some((path) => /^META-INF\/[^/]+\.(SF|RSA|DSA)$/i.test(path)) };
  return { schemaVersion: 1, analyzedAt: new Date().toISOString(), file: { name: file.name, size: file.size }, metadata, archive, classes: buildInventory(parsedClasses), security, build, source };
}
