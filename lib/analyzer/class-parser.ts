import type JSZip from "jszip";

export type MethodCall = { caller: string; owner: string; name: string; descriptor: string; opcode: "virtual" | "special" | "static" | "interface" };
export type ParsedClass = { path: string; name: string; javaVersion: number; methods: string[]; calls: MethodCall[]; byteText: string };
export type ClassInventory = { classCount: number; methodCount: number; callCount: number; javaVersions: number[]; classes: Array<Pick<ParsedClass, "path" | "name" | "javaVersion" | "methods"> & { callCount: number }> };

/** Dependency-free JVM class-file reader with Code-attribute invocation tracing. */
export async function parseClassFiles(zip: JSZip): Promise<ParsedClass[]> {
  const entries = Object.entries(zip.files).filter(([path, entry]) => !entry.dir && path.endsWith(".class"));
  const parsed = await Promise.all(entries.map(async ([path, entry]) => parseClass(path, await entry.async("uint8array"))));
  return parsed.filter((item): item is ParsedClass => item !== null);
}

export function buildInventory(classes: ParsedClass[]): ClassInventory {
  return { classCount: classes.length, methodCount: classes.reduce((total, item) => total + item.methods.length, 0), callCount: classes.reduce((total, item) => total + item.calls.length, 0), javaVersions: [...new Set(classes.map((item) => item.javaVersion))].sort((a, b) => a - b), classes: classes.slice(0, 12).map(({ path, name, javaVersion, methods, calls }) => ({ path, name, javaVersion, methods, callCount: calls.length })) };
}

export function parseClass(path: string, bytes: Uint8Array): ParsedClass | null {
  try {
    const reader = new Reader(bytes);
    if (reader.u4() !== 0xcafebabe) return null;
    reader.u2();
    const major = reader.u2();
    const pool = readConstantPool(reader);
    reader.u2();
    const thisClass = reader.u2();
    reader.u2();
    for (let count = reader.u2(); count > 0; count -= 1) reader.u2();
    skipMembers(reader);
    const parsedMethods = readMethods(reader, pool);
    const name = className(pool, thisClass) || path.replace(/\.class$/, "");
    return { path, name, javaVersion: major, methods: parsedMethods.map((item) => item.signature), calls: parsedMethods.flatMap((item) => item.calls), byteText: new TextDecoder("latin1").decode(bytes) };
  } catch { return null; }
}

type Constant = { tag: number; value?: string; nameIndex?: number; classIndex?: number; nameAndTypeIndex?: number; descriptorIndex?: number } | undefined;
function readConstantPool(reader: Reader): Constant[] {
  const pool: Constant[] = new Array(reader.u2());
  for (let index = 1; index < pool.length; index += 1) {
    const tag = reader.u1();
    if (tag === 1) pool[index] = { tag, value: new TextDecoder("utf-8").decode(reader.bytes(reader.u2())) };
    else if (tag === 7) pool[index] = { tag, nameIndex: reader.u2() };
    else if (tag === 9 || tag === 10 || tag === 11) pool[index] = { tag, classIndex: reader.u2(), nameAndTypeIndex: reader.u2() };
    else if (tag === 12) pool[index] = { tag, nameIndex: reader.u2(), descriptorIndex: reader.u2() };
    else { pool[index] = { tag }; skipConstant(reader, tag); if (tag === 5 || tag === 6) index += 1; }
  }
  return pool;
}

function readMethods(reader: Reader, pool: Constant[]) {
  const methods: Array<{ signature: string; calls: MethodCall[] }> = [];
  for (let count = reader.u2(); count > 0; count -= 1) {
    reader.u2();
    const name = utf(pool, reader.u2()) || "<unknown>";
    const descriptor = utf(pool, reader.u2()) || "";
    const calls: MethodCall[] = [];
    for (let attributes = reader.u2(); attributes > 0; attributes -= 1) {
      const attributeName = utf(pool, reader.u2());
      const length = reader.u4();
      if (attributeName === "Code") calls.push(...readCode(reader, pool, `${name}${descriptor}`));
      else reader.skip(length);
    }
    methods.push({ signature: `${name}${descriptor}`, calls });
  }
  return methods;
}

function readCode(reader: Reader, pool: Constant[], caller: string): MethodCall[] {
  reader.u2(); reader.u2();
  const code = reader.bytes(reader.u4());
  const calls = traceCalls(code, pool, caller);
  reader.skip(reader.u2() * 8);
  skipAttributes(reader);
  return calls;
}

function traceCalls(code: Uint8Array, pool: Constant[], caller: string) {
  const calls: MethodCall[] = [];
  for (let offset = 0; offset < code.length;) {
    const opcode = code[offset];
    if (opcode >= 0xb6 && opcode <= 0xb9 && offset + 2 < code.length) {
      const index = (code[offset + 1] << 8) | code[offset + 2];
      const resolved = methodReference(pool, index);
      if (resolved) calls.push({ caller, ...resolved, opcode: ({ 0xb6: "virtual", 0xb7: "special", 0xb8: "static", 0xb9: "interface" } as const)[opcode as 0xb6 | 0xb7 | 0xb8 | 0xb9] });
    }
    offset = nextInstruction(code, offset);
  }
  return calls;
}

function nextInstruction(code: Uint8Array, offset: number) {
  const opcode = code[offset];
  if (opcode === 0xaa) { const aligned = (offset + 4) & ~3; if (aligned + 12 > code.length) return code.length; const low = s4(code, aligned + 4); const high = s4(code, aligned + 8); return Math.min(code.length, aligned + 12 + Math.max(0, high - low + 1) * 4); }
  if (opcode === 0xab) { const aligned = (offset + 4) & ~3; if (aligned + 8 > code.length) return code.length; const pairs = s4(code, aligned + 4); return Math.min(code.length, aligned + 8 + Math.max(0, pairs) * 8); }
  if (opcode === 0xc4) return offset + (code[offset + 1] === 0x84 ? 6 : 4);
  return Math.min(code.length, offset + instructionLength(opcode));
}

function instructionLength(opcode: number) {
  if ([0x10, 0x12, 0x15, 0x16, 0x17, 0x18, 0x19, 0x36, 0x37, 0x38, 0x39, 0x3a, 0xa9, 0xbc].includes(opcode)) return 2;
  if ([0x11, 0x13, 0x14, 0x84, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xbb, 0xbd, 0xc0, 0xc1, 0xc6, 0xc7].includes(opcode)) return 3;
  if (opcode === 0xc5) return 4;
  if ([0xb9, 0xba, 0xc8, 0xc9].includes(opcode)) return 5;
  return 1;
}

function methodReference(pool: Constant[], index: number) { const reference = pool[index]; if (!reference || ![10, 11].includes(reference.tag) || reference.classIndex === undefined || reference.nameAndTypeIndex === undefined) return undefined; const pair = pool[reference.nameAndTypeIndex]; if (!pair || pair.tag !== 12 || pair.nameIndex === undefined || pair.descriptorIndex === undefined) return undefined; return { owner: className(pool, reference.classIndex) || "<unknown>", name: utf(pool, pair.nameIndex) || "<unknown>", descriptor: utf(pool, pair.descriptorIndex) || "" }; }
function s4(code: Uint8Array, offset: number) { return ((code[offset] << 24) | (code[offset + 1] << 16) | (code[offset + 2] << 8) | code[offset + 3]); }
function skipConstant(reader: Reader, tag: number) { const size: Record<number, number> = { 3: 4, 4: 4, 5: 8, 6: 8, 8: 2, 15: 3, 16: 2, 17: 4, 18: 4, 19: 2, 20: 2 }; const length = size[tag]; if (!length) throw new Error(`Unknown constant-pool tag ${tag}`); reader.skip(length); }
function skipMembers(reader: Reader) { for (let count = reader.u2(); count > 0; count -= 1) { reader.skip(6); skipAttributes(reader); } }
function skipAttributes(reader: Reader) { for (let count = reader.u2(); count > 0; count -= 1) { reader.u2(); reader.skip(reader.u4()); } }
function utf(pool: Constant[], index: number) { const item = pool[index]; return item?.tag === 1 ? item.value : undefined; }
function className(pool: Constant[], index: number) { const item = pool[index]; return item?.tag === 7 && item.nameIndex !== undefined ? utf(pool, item.nameIndex) : undefined; }
class Reader { private offset = 0; constructor(private readonly data: Uint8Array) {} u1() { this.guard(1); return this.data[this.offset++]; } u2() { return (this.u1() << 8) | this.u1(); } u4() { return (this.u2() * 65536) + this.u2(); } bytes(length: number) { this.guard(length); const value = this.data.slice(this.offset, this.offset + length); this.offset += length; return value; } skip(length: number) { this.guard(length); this.offset += length; } private guard(length: number) { if (this.offset + length > this.data.length) throw new Error("Unexpected end of class file"); } }
