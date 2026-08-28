import type JSZip from "jszip";
import { parse } from "yaml";

export type PluginMetadata = { source?: "paper-plugin.yml" | "plugin.yml"; name?: string; version?: string; main?: string; apiVersion?: string; authors?: string[]; contributors?: string[]; website?: string; description?: string; prefix?: string; load?: string; requiredDependencies: string[]; softDependencies: string[]; loadBefore: string[]; commands: string[]; permissions: string[]; libraries: string[] };

export async function parsePluginMetadata(zip: JSZip): Promise<PluginMetadata> {
  const source = zip.file("paper-plugin.yml") ? "paper-plugin.yml" : zip.file("plugin.yml") ? "plugin.yml" : undefined;
  if (!source) return emptyMetadata();
  const raw = await zip.file(source)!.async("text");
  let data: Record<string, unknown>;
  try { data = parse(raw) as Record<string, unknown>; } catch { throw new Error(`Could not parse ${source}.`); }
  const authors = Array.isArray(data.authors) ? data.authors.map(String) : data.author ? [String(data.author)] : undefined;
  const paperDependencies = objectValue(data.dependencies)?.server;
  const dependencyEntries = paperDependencies && typeof paperDependencies === "object" ? Object.entries(paperDependencies as Record<string, unknown>) : [];
  const requiredDependencies = [...stringArray(data.depend), ...dependencyEntries.filter(([, config]) => objectValue(config)?.required !== false).map(([name]) => name)];
  const softDependencies = [...stringArray(data.softdepend), ...dependencyEntries.filter(([, config]) => objectValue(config)?.required === false).map(([name]) => name)];
  return { source, name: stringValue(data.name), version: stringValue(data.version), main: stringValue(data.main), apiVersion: stringValue(data["api-version"]), authors, contributors: stringArray(data.contributors), website: stringValue(data.website), description: stringValue(data.description), prefix: stringValue(data.prefix), load: stringValue(data.load), requiredDependencies: unique(requiredDependencies), softDependencies: unique(softDependencies), loadBefore: stringArray(data.loadbefore), commands: Object.keys(objectValue(data.commands) || {}), permissions: Object.keys(objectValue(data.permissions) || {}), libraries: stringArray(data.libraries) };
}
function stringValue(value: unknown) { return typeof value === "string" || typeof value === "number" ? String(value) : undefined; }
function stringArray(value: unknown) { return Array.isArray(value) ? value.map(String) : value === undefined || value === null ? [] : [String(value)]; }
function objectValue(value: unknown) { return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined; }
function unique(values: string[]) { return [...new Set(values)]; }
function emptyMetadata(): PluginMetadata { return { requiredDependencies: [], softDependencies: [], loadBefore: [], commands: [], permissions: [], libraries: [] }; }
