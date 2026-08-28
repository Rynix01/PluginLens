import type { MethodCall, ParsedClass } from "./class-parser";

export type FindingSeverity = "info" | "medium" | "high";
export type FindingScope = "plugin" | "dependency" | "archive";
export type SecurityFinding = {
  id: string;
  category: string;
  title: string;
  description: string;
  severity: FindingSeverity;
  scope: FindingScope;
  scoreImpact: number;
  occurrences: number;
  locations: string[];
};
export type SecurityReport = {
  score: number;
  level: "low" | "medium" | "high" | "critical";
  findings: SecurityFinding[];
  scannedClasses: number;
};

type Rule = {
  id: string;
  category: string;
  title: string;
  description: string;
  severity: FindingSeverity;
  impact: number;
  matches: (call: MethodCall) => boolean;
};

const RULES: Rule[] = [
  {
    id: "network",
    category: "network",
    title: "Network capability",
    description: "Uses networking APIs. This is common for updates, webhooks, metrics and license checks; review the destination and transmitted data.",
    severity: "info",
    impact: 5,
    matches: ({ owner }) => startsWithAny(owner, ["java/net/URL", "java/net/Socket", "java/net/http/", "okhttp3/", "org/apache/http/"]),
  },
  {
    id: "filesystem",
    category: "filesystem",
    title: "Filesystem access",
    description: "Reads or writes files. Configuration, data storage and backups normally require this capability.",
    severity: "info",
    impact: 3,
    matches: ({ owner }) => startsWithAny(owner, ["java/io/File", "java/nio/file/Files", "java/nio/file/Path"]),
  },
  {
    id: "execution",
    category: "process",
    title: "Operating-system process execution",
    description: "Invokes an API that can start an external process. Runtime inspection calls such as availableProcessors are not included.",
    severity: "high",
    impact: 40,
    matches: ({ owner, name }) => (owner === "java/lang/Runtime" && name === "exec") || (owner === "java/lang/ProcessBuilder" && name === "start"),
  },
  {
    id: "reflection",
    category: "runtime",
    title: "Reflective or dynamic loading",
    description: "Uses reflection or dynamic class loading. Frameworks and bundled metrics libraries commonly use these APIs.",
    severity: "medium",
    impact: 8,
    matches: ({ owner, name }) => owner.startsWith("java/lang/reflect/") || (owner === "java/lang/Class" && name === "forName") || (owner === "java/lang/ClassLoader" && ["loadClass", "defineClass"].includes(name)),
  },
  {
    id: "native-loading",
    category: "native",
    title: "Native code loading",
    description: "Can load platform-native code into the server process.",
    severity: "high",
    impact: 35,
    matches: ({ owner, name }) => (owner === "java/lang/System" && ["load", "loadLibrary"].includes(name)) || owner.startsWith("com/sun/jna/"),
  },
  {
    id: "bytecode",
    category: "runtime",
    title: "Runtime bytecode manipulation",
    description: "Uses instrumentation or bytecode-generation APIs. This may be legitimate, but it expands runtime capabilities.",
    severity: "medium",
    impact: 18,
    matches: ({ owner }) => startsWithAny(owner, ["java/lang/instrument/", "sun/misc/Unsafe", "jdk/internal/misc/Unsafe", "org/objectweb/asm/", "net/bytebuddy/", "javassist/"]),
  },
  {
    id: "environment",
    category: "environment",
    title: "Environment inspection",
    description: "Reads environment variables or JVM system properties. This is informational unless combined with more sensitive behavior.",
    severity: "info",
    impact: 0,
    matches: ({ owner, name }) => owner === "java/lang/System" && ["getenv", "getProperty"].includes(name),
  },
];

/** Scores exact decoded calls and separates plugin-owned code from shaded dependencies. */
export function scanSecurity(classes: ParsedClass[], archivePaths: string[], mainClass?: string): SecurityReport {
  const findings: SecurityFinding[] = [];
  const firstPartyPrefix = pluginPackage(mainClass);

  for (const rule of RULES) {
    const matches = classes.flatMap((parsedClass) => parsedClass.calls
      .filter(rule.matches)
      .map((call) => ({ parsedClass, call })));
    if (!matches.length) continue;

    const pluginMatches = matches.filter(({ parsedClass }) => isPluginClass(parsedClass.name, firstPartyPrefix));
    const dependencyMatches = matches.filter(({ parsedClass }) => !isPluginClass(parsedClass.name, firstPartyPrefix));
    if (pluginMatches.length) findings.push(callFinding(rule, "plugin", pluginMatches));
    if (dependencyMatches.length) findings.push(callFinding(rule, "dependency", dependencyMatches));
  }

  const nativePaths = archivePaths.filter((path) => /\.(dll|so|dylib)$/i.test(path));
  if (nativePaths.length) findings.push(archiveFinding("native-binaries", "native", "Native binaries bundled", "Contains platform-native binaries. Their behavior cannot be fully established from JVM bytecode alone.", "high", 25, nativePaths));
  const executablePaths = archivePaths.filter((path) => /\.(exe|bat|cmd|ps1|sh)$/i.test(path));
  if (executablePaths.length) findings.push(archiveFinding("executable-resources", "process", "Executable resources bundled", "Contains scripts or executable files that warrant manual review.", "high", 30, executablePaths));
  const embeddedJars = archivePaths.filter((path) => path.toLowerCase().endsWith(".jar"));
  if (embeddedJars.length) findings.push(archiveFinding("embedded-jars", "archive", "Embedded JARs", "Contains nested Java archives. These are reported as inventory, not treated as malicious by themselves.", "info", 0, embeddedJars));

  const score = Math.min(100, findings.reduce((total, finding) => total + finding.scoreImpact, 0));
  return { score, level: score >= 60 ? "critical" : score >= 30 ? "high" : score >= 10 ? "medium" : "low", findings, scannedClasses: classes.length };
}

function callFinding(rule: Rule, scope: "plugin" | "dependency", matches: Array<{ parsedClass: ParsedClass; call: MethodCall }>): SecurityFinding {
  const dependency = scope === "dependency";
  return {
    id: dependency ? `${rule.id}-dependency` : rule.id,
    category: rule.category,
    title: rule.title,
    description: dependency ? `${rule.description} Detected only inside bundled dependency code, so it does not increase the plugin risk score.` : rule.description,
    severity: dependency ? "info" : rule.severity,
    scope,
    scoreImpact: dependency ? 0 : rule.impact,
    occurrences: matches.length,
    locations: unique(matches.map(({ parsedClass, call }) => `${parsedClass.name}#${call.caller} → ${call.owner}.${call.name}${call.descriptor}`)).slice(0, 8),
  };
}

function archiveFinding(id: string, category: string, title: string, description: string, severity: FindingSeverity, scoreImpact: number, paths: string[]): SecurityFinding {
  return { id, category, title, description, severity, scope: "archive", scoreImpact, occurrences: paths.length, locations: paths.slice(0, 8) };
}

function pluginPackage(mainClass?: string) {
  if (!mainClass) return undefined;
  const normalized = mainClass.replace(/\./g, "/");
  const divider = normalized.lastIndexOf("/");
  return divider > 0 ? normalized.slice(0, divider) : undefined;
}

function isPluginClass(className: string, prefix?: string) { return !prefix || className === prefix || className.startsWith(`${prefix}/`); }
function startsWithAny(value: string, prefixes: string[]) { return prefixes.some((prefix) => value.startsWith(prefix)); }
function unique(values: string[]) { return [...new Set(values)]; }
