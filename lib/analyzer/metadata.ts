import type JSZip from "jszip";
import { parse } from "yaml";

export type PluginMetadata = { source?: "paper-plugin.yml" | "plugin.yml"; name?: string; version?: string; main?: string; apiVersion?: string; authors?: string[]; website?: string };

export async function parsePluginMetadata(zip: JSZip): Promise<PluginMetadata> {
  const source = zip.file("paper-plugin.yml") ? "paper-plugin.yml" : zip.file("plugin.yml") ? "plugin.yml" : undefined;
  if (!source) return {};
  const raw = await zip.file(source)!.async("text");
  let data: Record<string, unknown>;
  try { data = parse(raw) as Record<string, unknown>; } catch { throw new Error(`Could not parse ${source}.`); }
  const authors = Array.isArray(data.authors) ? data.authors.map(String) : data.author ? [String(data.author)] : undefined;
  return { source, name: stringValue(data.name), version: stringValue(data.version), main: stringValue(data.main), apiVersion: stringValue(data["api-version"]), authors, website: stringValue(data.website) };
}
function stringValue(value: unknown) { return typeof value === "string" || typeof value === "number" ? String(value) : undefined; }
