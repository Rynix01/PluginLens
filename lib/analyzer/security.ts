import type { ParsedClass } from "./class-parser";

export type RiskLevel = "low" | "medium" | "high" | "critical";
export type FindingCategory = "network" | "filesystem" | "execution" | "reflection" | "obfuscation" | "native" | "bytecode" | "archive" | "environment";
export type SecurityFinding = { id: string; category: FindingCategory; title: string; description: string; severity: "info" | "medium" | "high"; occurrences: number; locations: string[] };
export type SecurityReport = { score: number; level: RiskLevel; findings: SecurityFinding[]; scannedClasses: number };

type Rule = Omit<SecurityFinding, "occurrences" | "locations"> & { patterns: string[]; weight: number };

const RULES: Rule[] = [
  { id: "network", category: "network", title: "Network capability", description: "References HTTP, URL, socket, or web client APIs.", severity: "medium", weight: 18, patterns: ["java/net/URL", "java/net/Socket", "java/net/http", "okhttp3/", "org/apache/http"] },
  { id: "filesystem", category: "filesystem", title: "Filesystem access", description: "References APIs that can read or write local files.", severity: "medium", weight: 14, patterns: ["java/io/File", "java/nio/file/Files", "java/nio/file/Path"] },
  { id: "execution", category: "execution", title: "Process execution", description: "References APIs capable of launching an operating-system process.", severity: "high", weight: 35, patterns: ["java/lang/Runtime", "java/lang/ProcessBuilder"] },
  { id: "reflection", category: "reflection", title: "Reflective loading", description: "References reflection or dynamic class-loading APIs.", severity: "medium", weight: 15, patterns: ["java/lang/reflect", "java/lang/ClassLoader", "forName"] },
  { id: "native-loading", category: "native", title: "Native code loading", description: "Can load native DLL, SO, or dylib code outside the JVM sandbox.", severity: "high", weight: 30, patterns: ["java/lang/System.load", "java/lang/System.loadLibrary", "com/sun/jna"] },
  { id: "bytecode-manipulation", category: "bytecode", title: "Runtime bytecode manipulation", description: "References instrumentation, Unsafe, ASM, Byte Buddy, or Javassist APIs.", severity: "high", weight: 24, patterns: ["java/lang/instrument", "sun/misc/Unsafe", "jdk/internal/misc/Unsafe", "org/objectweb/asm", "net/bytebuddy", "javassist/"] },
  { id: "environment", category: "environment", title: "Environment inspection", description: "Reads environment variables or JVM/system properties.", severity: "info", weight: 6, patterns: ["java/lang/System.getenv", "java/lang/System.getProperty"] },
];

/** Uses decoded method calls when available and falls back to constant-pool signals. */
export function scanSecurity(classes: ParsedClass[], archivePaths: string[] = []): SecurityReport {
  const findings = RULES.map((rule) => findingFor(rule, classes)).filter((finding): finding is SecurityFinding => finding !== null);
  const obfuscation = detectObfuscation(classes.map(({ path }) => path));
  if (obfuscation) findings.push(obfuscation);
  findings.push(...archiveFindings(archivePaths));
  const score = Math.min(100, findings.reduce((total, finding) => total + (RULES.find((rule) => rule.id === finding.id)?.weight ?? ({ "native-binaries": 26, "executable-resources": 32, "embedded-jars": 7, obfuscation: 18 } as Record<string, number>)[finding.id] ?? 12), 0));
  return { score, level: score >= 70 ? "critical" : score >= 45 ? "high" : score >= 20 ? "medium" : "low", findings, scannedClasses: classes.length };
}
function archiveFindings(paths: string[]): SecurityFinding[] { const findings: SecurityFinding[] = []; const native = paths.filter((path) => /\.(dll|so|dylib)$/i.test(path)); const executables = paths.filter((path) => /\.(exe|bat|cmd|ps1|vbs)$/i.test(path)); const nestedJars = paths.filter((path) => path.toLowerCase().endsWith(".jar")); if (native.length) findings.push({ id: "native-binaries", category: "native", title: "Bundled native binaries", description: "The archive contains platform-native executable libraries.", severity: "high", occurrences: native.length, locations: native.slice(0, 6) }); if (executables.length) findings.push({ id: "executable-resources", category: "archive", title: "Bundled executable resources", description: "The archive includes operating-system scripts or executables.", severity: "high", occurrences: executables.length, locations: executables.slice(0, 6) }); if (nestedJars.length) findings.push({ id: "embedded-jars", category: "archive", title: "Embedded JAR dependencies", description: "Nested JARs increase the amount of code that needs review.", severity: "info", occurrences: nestedJars.length, locations: nestedJars.slice(0, 6) }); return findings; }

function findingFor(rule: Rule, classes: ParsedClass[]): SecurityFinding | null {
  const callMatches = classes.flatMap((item) => item.calls.filter((call) => rule.patterns.some((pattern) => `${call.owner}.${call.name}`.includes(pattern))).map((call) => ({ className: item.name, call })));
  if (callMatches.length) return { id: rule.id, category: rule.category, title: rule.title, description: rule.description, severity: rule.severity, occurrences: callMatches.length, locations: callMatches.slice(0, 6).map(({ className, call }) => `${className}#${call.caller} → ${call.owner}.${call.name}${call.descriptor}`) };
  const matching = classes.map((item) => ({ name: item.name, occurrences: rule.patterns.reduce((total, pattern) => total + count(item.byteText, pattern), 0) })).filter((item) => item.occurrences > 0);
  const occurrences = matching.reduce((total, item) => total + item.occurrences, 0);
  return occurrences ? { id: rule.id, category: rule.category, title: rule.title, description: rule.description, severity: rule.severity, occurrences, locations: matching.slice(0, 4).map((item) => item.name) } : null;
}
function detectObfuscation(paths: string[]): SecurityFinding | null {
  const leafNames = paths.map((path) => path.slice(path.lastIndexOf("/") + 1, -6));
  const shortNames = leafNames.filter((name) => /^[a-zA-Z]{1,2}\d*$/.test(name));
  if (paths.length < 12 || shortNames.length / paths.length < 0.65) return null;
  return { id: "obfuscation", category: "obfuscation", title: "Possible name obfuscation", description: "Most class names are unusually short. This can be normal for optimized builds, but makes review harder.", severity: "medium", occurrences: shortNames.length, locations: paths.filter((path) => /^[^/]+\/[a-zA-Z]{1,2}\d*\.class$/.test(path)).slice(0, 4) };
}
function count(value: string, needle: string) { let total = 0; let index = value.indexOf(needle); while (index !== -1) { total += 1; index = value.indexOf(needle, index + needle.length); } return total; }
