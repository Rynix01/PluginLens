import type JSZip from "jszip";

export type ParsedClass = { path: string; name: string; javaVersion: number; methods: string[]; byteText: string };
export type ClassInventory = { classCount: number; methodCount: number; javaVersions: number[]; classes: Array<Pick<ParsedClass, "path" | "name" | "javaVersion" | "methods">> };

/** A small, dependency-free JVM class-file reader for structure and constant-pool inspection. */
export async function parseClassFiles(zip: JSZip): Promise<ParsedClass[]> {
  const entries = Object.entries(zip.files).filter(([path, entry]) => !entry.dir && path.endsWith(".class"));
  const parsed = await Promise.all(entries.map(async ([path, entry]) => parseClass(path, await entry.async("uint8array"))));
  return parsed.filter((item): item is ParsedClass => item !== null);
}

export function buildInventory(classes: ParsedClass[]): ClassInventory {
  return { classCount: classes.length, methodCount: classes.reduce((total, item) => total + item.methods.length, 0), javaVersions: [...new Set(classes.map((item) => item.javaVersion))].sort((a, b) => a - b), classes: classes.slice(0, 12).map(({ path, name, javaVersion, methods }) => ({ path, name, javaVersion, methods })) };
}

function parseClass(path: string, bytes: Uint8Array): ParsedClass | null {
  try {
    const reader = new Reader(bytes);
    if (reader.u4() !== 0xcafebabe) return null;
    reader.u2(); // minor
    const major = reader.u2();
    const pool = readConstantPool(reader);
    reader.u2(); // access flags
    const thisClass = reader.u2();
    reader.u2(); // super class
    const interfaceCount = reader.u2();
    for (let index = 0; index < interfaceCount; index += 1) reader.u2();
    skipMembers(reader);
    const methods = readMethods(reader, pool);
    const name = className(pool, thisClass) || path.replace(/\.class$/, "");
    return { path, name, javaVersion: major, methods, byteText: new TextDecoder("latin1").decode(bytes) };
  } catch { return null; }
}

type Constant = { tag: number; value?: string; nameIndex?: number } | undefined;
function readConstantPool(reader: Reader): Constant[] {
  const pool: Constant[] = new Array(reader.u2());
  for (let index = 1; index < pool.length; index += 1) {
    const tag = reader.u1();
    if (tag === 1) {
      pool[index] = { tag, value: new TextDecoder("utf-8").decode(reader.bytes(reader.u2())) };
    } else if (tag === 7) {
      pool[index] = { tag, nameIndex: reader.u2() };
    } else {
      pool[index] = { tag };
      skipConstant(reader, tag);
      if (tag === 5 || tag === 6) index += 1;
    }
  }
  return pool;
}
function skipConstant(reader: Reader, tag: number) { const size: Record<number, number> = { 3: 4, 4: 4, 5: 8, 6: 8, 8: 2, 9: 4, 10: 4, 11: 4, 12: 4, 15: 3, 16: 2, 17: 4, 18: 4, 19: 2, 20: 2 }; const length = size[tag]; if (!length) throw new Error("Unknown constant-pool tag"); reader.skip(length); }
function skipMembers(reader: Reader) { const count = reader.u2(); for (let index = 0; index < count; index += 1) { reader.skip(6); skipAttributes(reader); } }
function readMethods(reader: Reader, pool: Constant[]): string[] { const methods: string[] = []; const count = reader.u2(); for (let index = 0; index < count; index += 1) { reader.u2(); const nameIndex = reader.u2(); const descriptorIndex = reader.u2(); methods.push(`${utf(pool, nameIndex) || "<unknown>"}${utf(pool, descriptorIndex) || ""}`); skipAttributes(reader); } return methods; }
function skipAttributes(reader: Reader) { const count = reader.u2(); for (let index = 0; index < count; index += 1) { reader.u2(); reader.skip(reader.u4()); } }
function utf(pool: Constant[], index: number) { const item = pool[index]; return item?.tag === 1 ? item.value : undefined; }
function className(pool: Constant[], index: number) { const item = pool[index]; return item?.tag === 7 && item.nameIndex !== undefined ? utf(pool, item.nameIndex) : undefined; }
class Reader { private offset = 0; constructor(private readonly data: Uint8Array) {} u1() { this.guard(1); return this.data[this.offset++]; } u2() { return (this.u1() << 8) | this.u1(); } u4() { return (this.u2() * 65536) + this.u2(); } bytes(length: number) { this.guard(length); const value = this.data.slice(this.offset, this.offset + length); this.offset += length; return value; } skip(length: number) { this.guard(length); this.offset += length; } private guard(length: number) { if (this.offset + length > this.data.length) throw new Error("Unexpected end of class file"); } }
