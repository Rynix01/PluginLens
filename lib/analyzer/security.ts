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
  dependencyImpact?: number;
  matches: (call: MethodCall) => boolean;
};

// Only packages with a strong, recognizable library identity are discounted.
// Unknown packages must remain first-party: malware can choose any package name.
const KNOWN_DEPENDENCY_PREFIXES = [
  "org/bstats/",
  "com/google/",
  "com/fasterxml/",
  "org/apache/commons/",
  "org/apache/http/",
  "org/slf4j/",
  "ch/qos/logback/",
  "org/yaml/snakeyaml/",
  "com/github/benmanes/caffeine/",
  "net/kyori/",
  "kotlin/",
  "kotlinx/",
];

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
    id: "websocket",
    category: "network",
    title: "Persistent WebSocket channel",
    description: "Uses a bidirectional WebSocket channel capable of receiving commands or payloads while the server is running.",
    severity: "medium",
    impact: 10,
    matches: ({ owner }) => startsWithAny(owner, ["java/net/http/WebSocket", "javax/websocket/", "jakarta/websocket/", "org/java_websocket/", "okhttp3/WebSocket"]),
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
    dependencyImpact: 40,
    matches: ({ owner, name }) => (owner === "java/lang/Runtime" && name === "exec") || (owner === "java/lang/ProcessBuilder" && name === "start"),
  },
  {
    id: "reflection",
    category: "runtime",
    title: "Reflective or dynamic loading",
    description: "Uses reflection or dynamic class loading. Frameworks and bundled metrics libraries commonly use these APIs.",
    severity: "medium",
    impact: 8,
    matches: ({ owner, name }) => owner.startsWith("java/lang/reflect/") || (owner === "java/lang/Class" && name === "forName") || (owner === "java/lang/ClassLoader" && name === "loadClass"),
  },
  {
    id: "dynamic-code-execution",
    category: "execution",
    title: "Dynamic code compilation or evaluation",
    description: "Uses APIs capable of compiling, defining, or evaluating code supplied while the server is running.",
    severity: "high",
    impact: 50,
    dependencyImpact: 50,
    matches: ({ owner, name }) =>
      (owner === "javax/tools/ToolProvider" && name === "getSystemJavaCompiler") ||
      (owner === "javax/tools/JavaCompiler" && ["getTask", "run"].includes(name)) ||
      (owner === "javax/script/ScriptEngine" && name === "eval") ||
      (owner === "jdk/jshell/JShell" && name === "eval") ||
      (owner === "groovy/lang/GroovyShell" && ["evaluate", "parse"].includes(name)) ||
      (owner === "java/lang/ClassLoader" && name === "defineClass") ||
      (owner === "java/lang/invoke/MethodHandles$Lookup" && name === "defineClass"),
  },
  {
    id: "jar-mutation",
    category: "persistence",
    title: "JAR archive modification",
    description: "Writes ZIP/JAR entries and can create or modify plugin archives.",
    severity: "medium",
    impact: 15,
    dependencyImpact: 10,
    matches: ({ owner, name }) => startsWithAny(owner, ["java/util/jar/JarOutputStream", "java/util/zip/ZipOutputStream"]) && ["putNextEntry", "write"].includes(name),
  },
  {
    id: "native-loading",
    category: "native",
    title: "Native code loading",
    description: "Can load platform-native code into the server process.",
    severity: "high",
    impact: 35,
    dependencyImpact: 35,
    matches: ({ owner, name }) => (owner === "java/lang/System" && ["load", "loadLibrary"].includes(name)) || owner.startsWith("com/sun/jna/"),
  },
  {
    id: "bytecode",
    category: "runtime",
    title: "Runtime bytecode manipulation",
    description: "Uses instrumentation or bytecode-generation APIs. This may be legitimate, but it expands runtime capabilities.",
    severity: "medium",
    impact: 18,
    dependencyImpact: 12,
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

    const pluginMatches = matches.filter(({ parsedClass }) => classifyClass(parsedClass.name, firstPartyPrefix) === "plugin");
    const dependencyMatches = matches.filter(({ parsedClass }) => classifyClass(parsedClass.name, firstPartyPrefix) === "dependency");
    if (pluginMatches.length) findings.push(callFinding(rule, "plugin", pluginMatches));
    if (dependencyMatches.length) findings.push(callFinding(rule, "dependency", dependencyMatches));
  }

  findings.push(...behaviorChains(classes, firstPartyPrefix));

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
  const scoreImpact = dependency ? rule.dependencyImpact ?? 0 : rule.impact;
  return {
    id: dependency ? `${rule.id}-dependency` : rule.id,
    category: rule.category,
    title: rule.title,
    description: dependency ? `${rule.description} Detected inside a known bundled library.${scoreImpact ? " This behavior is sensitive enough that library scope does not suppress it." : " Ordinary library use does not increase the plugin risk score."}` : rule.description,
    severity: dependency && !scoreImpact ? "info" : rule.severity,
    scope,
    scoreImpact,
    occurrences: matches.length,
    locations: unique(matches.map(({ parsedClass, call }) => `${parsedClass.name}#${call.caller} → ${call.owner}.${call.name}${call.descriptor}`)).slice(0, 8),
  };
}

function archiveFinding(id: string, category: string, title: string, description: string, severity: FindingSeverity, scoreImpact: number, paths: string[]): SecurityFinding {
  return { id, category, title, description, severity, scope: "archive", scoreImpact, occurrences: paths.length, locations: paths.slice(0, 8) };
}

function behaviorChains(classes: ParsedClass[], firstPartyPrefix?: string): SecurityFinding[] {
  const pluginClasses = classes.filter((parsedClass) => classifyClass(parsedClass.name, firstPartyPrefix) === "plugin");
  const websocketClasses = pluginClasses.filter((parsedClass) => parsedClass.calls.some(isWebSocketCall) || includesAny(parsedClass.byteText, ["java/net/http/WebSocket", "javax/websocket/", "jakarta/websocket/", "org/java_websocket/", "okhttp3/WebSocket"]));
  const dynamicCodeClasses = pluginClasses.filter((parsedClass) => parsedClass.calls.some(isDynamicCodeCall));
  const archiveWriterClasses = pluginClasses.filter((parsedClass) => parsedClass.calls.some(isJarWriteCall));
  const copyClasses = pluginClasses.filter((parsedClass) => parsedClass.calls.some(({ owner, name }) => (owner === "java/nio/file/Files" && ["copy", "move", "write"].includes(name)) || (owner === "java/io/FileOutputStream" && name === "write")));
  const pluginTargetClasses = pluginClasses.filter((parsedClass) => parsedClass.calls.some(({ owner, name }) => (owner === "org/bukkit/plugin/PluginManager" && name === "getPlugins") || (owner.endsWith("JavaPlugin") && name === "getFile")) || includesAny(parsedClass.byteText.toLowerCase(), ["plugins/", "plugins\\", ".jar"]));
  const findings: SecurityFinding[] = [];

  if (websocketClasses.length && dynamicCodeClasses.length) {
    findings.push(compositeFinding(
      "remote-code-chain",
      "execution",
      "Remote code execution chain",
      "Combines a persistent WebSocket input channel with runtime code compilation, definition, or evaluation. This can allow code received from a remote endpoint to execute inside the server.",
      35,
      [...websocketClasses, ...dynamicCodeClasses],
    ));
  }

  if (archiveWriterClasses.length && copyClasses.length && pluginTargetClasses.length) {
    findings.push(compositeFinding(
      "plugin-propagation-chain",
      "persistence",
      "Possible plugin self-propagation",
      "Combines plugin/JAR targeting, archive modification, and file-copy behavior. This pattern can rewrite or copy code into other plugin archives.",
      45,
      [...archiveWriterClasses, ...copyClasses, ...pluginTargetClasses],
    ));
  }

  return findings;
}

function compositeFinding(id: string, category: string, title: string, description: string, scoreImpact: number, classes: ParsedClass[]): SecurityFinding {
  const locations = unique(classes.map((parsedClass) => parsedClass.name)).slice(0, 8);
  return { id, category, title, description, severity: "high", scope: "plugin", scoreImpact, occurrences: locations.length, locations };
}

function isWebSocketCall({ owner }: MethodCall) { return startsWithAny(owner, ["java/net/http/WebSocket", "javax/websocket/", "jakarta/websocket/", "org/java_websocket/", "okhttp3/WebSocket"]); }
function isDynamicCodeCall({ owner, name }: MethodCall) {
  return (owner === "javax/tools/ToolProvider" && name === "getSystemJavaCompiler") ||
    (owner === "javax/tools/JavaCompiler" && ["getTask", "run"].includes(name)) ||
    (owner === "javax/script/ScriptEngine" && name === "eval") ||
    (owner === "jdk/jshell/JShell" && name === "eval") ||
    (owner === "groovy/lang/GroovyShell" && ["evaluate", "parse"].includes(name)) ||
    (owner === "java/lang/ClassLoader" && name === "defineClass") ||
    (owner === "java/lang/invoke/MethodHandles$Lookup" && name === "defineClass");
}
function isJarWriteCall({ owner, name }: MethodCall) { return startsWithAny(owner, ["java/util/jar/JarOutputStream", "java/util/zip/ZipOutputStream"]) && ["putNextEntry", "write"].includes(name); }
function includesAny(value: string, needles: string[]) { return needles.some((needle) => value.includes(needle)); }

function pluginPackage(mainClass?: string) {
  if (!mainClass) return undefined;
  const normalized = mainClass.replace(/\./g, "/");
  const divider = normalized.lastIndexOf("/");
  return divider > 0 ? normalized.slice(0, divider) : undefined;
}

function classifyClass(className: string, firstPartyPrefix?: string): "plugin" | "dependency" {
  if (firstPartyPrefix && (className === firstPartyPrefix || className.startsWith(`${firstPartyPrefix}/`))) return "plugin";
  return startsWithAny(className, KNOWN_DEPENDENCY_PREFIXES) ? "dependency" : "plugin";
}
function startsWithAny(value: string, prefixes: string[]) { return prefixes.some((prefix) => value.startsWith(prefix)); }
function unique(values: string[]) { return [...new Set(values)]; }
