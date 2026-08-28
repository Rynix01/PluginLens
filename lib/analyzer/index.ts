import JSZip from "jszip";
import { parsePluginMetadata, type PluginMetadata } from "./metadata";
import { scanSecurity, type SecurityReport } from "./security";

export type AnalysisResult = { file: { name: string; size: number }; metadata: PluginMetadata; archive: { entryCount: number; classCount: number; resourceCount: number }; security: SecurityReport };

/** Browser-only orchestrator. Future scanners receive this local ZIP model, never an uploaded file. */
export async function analyzePluginJar(file: File): Promise<AnalysisResult> {
  let zip: JSZip;
  try { zip = await JSZip.loadAsync(await file.arrayBuffer()); } catch { throw new Error("This file is not a readable JAR/ZIP archive."); }
  const paths = Object.keys(zip.files).filter((path) => !zip.files[path].dir);
  const metadata = await parsePluginMetadata(zip);
  const security = await scanSecurity(zip);
  return { file: { name: file.name, size: file.size }, metadata, archive: { entryCount: paths.length, classCount: paths.filter((path) => path.endsWith(".class")).length, resourceCount: paths.filter((path) => !path.endsWith(".class")).length }, security };
}
