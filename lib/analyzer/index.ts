import JSZip from "jszip";
import { inspectBuild, type BuildIdentity } from "./build";
import { buildInventory, parseClassFiles, type ClassInventory } from "./class-parser";
import { parsePluginMetadata, type PluginMetadata } from "./metadata";
import { scanSecurity, type SecurityReport } from "./security";
import { inspectSource, type SourceIdentity } from "./source";

export type ArchiveReport = { entryCount: number; classCount: number; resourceCount: number; embeddedJarCount: number; nativeLibraryCount: number; serviceProviderCount: number; signed: boolean };
export type AnalysisResult = { schemaVersion: 1; analyzedAt: string; file: { name: string; size: number }; metadata: PluginMetadata; archive: ArchiveReport; classes: ClassInventory; security: SecurityReport; build: BuildIdentity; source: SourceIdentity };

/** Browser-only orchestrator. Future scanners receive this local ZIP model, never an uploaded file. */
export async function analyzePluginJar(file: File): Promise<AnalysisResult> {
  let zip: JSZip;
  const bytes = await file.arrayBuffer();
  try { zip = await JSZip.loadAsync(bytes); } catch { throw new Error("This file is not a readable JAR/ZIP archive."); }
  const paths = Object.keys(zip.files).filter((path) => !zip.files[path].dir);
  const metadata = await parsePluginMetadata(zip);
  const parsedClasses = await parseClassFiles(zip);
  const security = scanSecurity(parsedClasses, paths);
  const build = await inspectBuild(zip, bytes, metadata.version);
  const source = await inspectSource(zip, metadata.website, metadata.version || build.implementationVersion);
  const archive: ArchiveReport = { entryCount: paths.length, classCount: paths.filter((path) => path.endsWith(".class")).length, resourceCount: paths.filter((path) => !path.endsWith(".class")).length, embeddedJarCount: paths.filter((path) => path.toLowerCase().endsWith(".jar")).length, nativeLibraryCount: paths.filter((path) => /\.(dll|so|dylib)$/i.test(path)).length, serviceProviderCount: paths.filter((path) => path.startsWith("META-INF/services/")).length, signed: paths.some((path) => /^META-INF\/[^/]+\.(SF|RSA|DSA)$/i.test(path)) };
  return { schemaVersion: 1, analyzedAt: new Date().toISOString(), file: { name: file.name, size: file.size }, metadata, archive, classes: buildInventory(parsedClasses), security, build, source };
}
