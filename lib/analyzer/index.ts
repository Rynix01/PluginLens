import JSZip from "jszip";
import { inspectBuild, type BuildIdentity } from "./build";
import { buildInventory, parseClassFiles, type ClassInventory } from "./class-parser";
import { parsePluginMetadata, type PluginMetadata } from "./metadata";
import { scanSecurity, type SecurityReport } from "./security";

export type AnalysisResult = { file: { name: string; size: number }; metadata: PluginMetadata; archive: { entryCount: number; classCount: number; resourceCount: number }; classes: ClassInventory; security: SecurityReport; build: BuildIdentity };

/** Browser-only orchestrator. Future scanners receive this local ZIP model, never an uploaded file. */
export async function analyzePluginJar(file: File): Promise<AnalysisResult> {
  let zip: JSZip;
  const bytes = await file.arrayBuffer();
  try { zip = await JSZip.loadAsync(bytes); } catch { throw new Error("This file is not a readable JAR/ZIP archive."); }
  const paths = Object.keys(zip.files).filter((path) => !zip.files[path].dir);
  const metadata = await parsePluginMetadata(zip);
  const parsedClasses = await parseClassFiles(zip);
  const security = scanSecurity(parsedClasses);
  const build = await inspectBuild(zip, bytes);
  return { file: { name: file.name, size: file.size }, metadata, archive: { entryCount: paths.length, classCount: paths.filter((path) => path.endsWith(".class")).length, resourceCount: paths.filter((path) => !path.endsWith(".class")).length }, classes: buildInventory(parsedClasses), security, build };
}
