import JSZip from "jszip";
import { describe, expect, it } from "vitest";
import { inspectBuild } from "../lib/analyzer/build";
import { parseClass, type ParsedClass } from "../lib/analyzer/class-parser";
import { parsePluginMetadata } from "../lib/analyzer/metadata";
import { scanSecurity } from "../lib/analyzer/security";
import { githubRepository, inspectSource } from "../lib/analyzer/source";

const CLASS_FIXTURE = "yv66vgAAAEUAHAoAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+AQADKClWCgAIAAkHAAoMAAsADAEAEWphdmEvbGFuZy9SdW50aW1lAQAKZ2V0UnVudGltZQEAFSgpTGphdmEvbGFuZy9SdW50aW1lOwoACAAODAAPABABAARleGVjAQAnKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1Byb2Nlc3M7BwASAQABVAEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAAF4AQAVKExqYXZhL2xhbmcvU3RyaW5nOylWAQAKRXhjZXB0aW9ucwcAGQEAE2phdmEvbGFuZy9FeGNlcHRpb24BAApTb3VyY2VGaWxlAQAGVC5qYXZhACEAEQACAAAAAAACAAEABQAGAAEAEwAAAB0AAQABAAAABSq3AAGxAAAAAQAUAAAABgABAAAAAQABABUAFgACABMAAAAlAAIAAgAAAAm4AAcrtgANV7EAAAABABQAAAAKAAIAAAADAAgABAAXAAAABAABABgAAQAaAAAAAgAb";

describe("PluginLens analyzers", () => {
  it("parses Bukkit descriptor surface", async () => {
    const zip = new JSZip();
    zip.file("plugin.yml", "name: Example\nversion: 2.4.1\nmain: dev.example.Main\napi-version: '1.21'\ndepend: [Vault]\nsoftdepend: [PlaceholderAPI]\ncommands:\n  example: {}\npermissions:\n  example.use: {}\nlibraries: [com.example:library:1.0]\n");
    const metadata = await parsePluginMetadata(zip);
    expect(metadata).toMatchObject({ name: "Example", version: "2.4.1", requiredDependencies: ["Vault"], softDependencies: ["PlaceholderAPI"], commands: ["example"], permissions: ["example.use"] });
  });

  it("detects Gradle build evidence and fingerprints locally", async () => {
    const zip = new JSZip();
    zip.file("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\nCreated-By: Gradle 8.10\r\nImplementation-Version: 2.4.1\r\nBuild-Jdk-Spec: 21\r\n");
    const bytes = await zip.generateAsync({ type: "arraybuffer" });
    const build = await inspectBuild(zip, bytes, "2.4.1");
    expect(build.tool).toBe("Gradle");
    expect(build.implementationVersion).toBe("2.4.1");
    expect(build.buildJdk).toBe("21");
    expect(build.sha256).toMatch(/^[a-f0-9]{64}$/);
  });

  it("decodes JVM method calls and maps security evidence", () => {
    const parsed = parseClass("T.class", Uint8Array.from(Buffer.from(CLASS_FIXTURE, "base64")));
    expect(parsed?.calls.some((call) => call.owner === "java/lang/Runtime" && call.name === "exec" && call.caller.startsWith("x("))).toBe(true);
    const report = scanSecurity(parsed ? [parsed] : [], ["native/payload.dll", "scripts/install.ps1"]);
    expect(report.findings.map((finding) => finding.id)).toEqual(expect.arrayContaining(["execution", "native-binaries", "executable-resources"]));
  });

  it("discovers GitHub repositories and version tag candidates", async () => {
    const zip = new JSZip();
    zip.file("META-INF/maven/com.github.patrickfav/bytes-java/pom.xml", "<project><artifactId>bytes-java</artifactId><scm><url>https://github.com/patrickfav/bytes-java.git</url></scm></project>");
    zip.file("META-INF/maven/dev.example/ExamplePlugin/pom.xml", "<project><artifactId>ExamplePlugin</artifactId><scm><url>https://github.com/example/ExamplePlugin.git</url></scm></project>");
    const source = await inspectSource(zip, undefined, "2.4.1", { pluginName: "ExamplePlugin", artifact: "ExamplePlugin", mainClass: "dev.example.ExamplePlugin" });
    expect(source.repository?.url).toBe("https://github.com/example/ExamplePlugin");
    expect(source.tagCandidates).toEqual(expect.arrayContaining(["2.4.1", "v2.4.1", "release-2.4.1"]));
    expect(githubRepository("git@github.com:owner/repo.git")?.url).toBe("https://github.com/owner/repo");
  });

  it("does not mistake shaded dependency metadata for the plugin repository", async () => {
    const zip = new JSZip();
    zip.file("META-INF/maven/com.github.patrickfav/bytes-java/pom.xml", "<project><artifactId>bytes-java</artifactId><url>https://github.com/patrickfav/bytes-java</url></project>");
    const source = await inspectSource(zip, undefined, "2.0", { pluginName: "NexubyCore", artifact: "NexubyCore", mainClass: "tr.net.nexuby.NexubyCore" });
    expect(source.repository).toBeUndefined();
  });

  it("keeps harmless Runtime calls out of process execution and discounts bundled dependencies", () => {
    const dependencyClass: ParsedClass = {
      path: "org/bstats/bukkit/Metrics.class",
      name: "org/bstats/bukkit/Metrics",
      javaVersion: 65,
      methods: ["appendPlatformData()V"],
      byteText: "",
      calls: [
        { caller: "appendPlatformData()V", owner: "java/lang/Runtime", name: "getRuntime", descriptor: "()Ljava/lang/Runtime;", opcode: "static" },
        { caller: "appendPlatformData()V", owner: "java/lang/Runtime", name: "availableProcessors", descriptor: "()I", opcode: "virtual" },
        { caller: "appendPlatformData()V", owner: "java/lang/Class", name: "forName", descriptor: "(Ljava/lang/String;)Ljava/lang/Class;", opcode: "static" },
        { caller: "appendPlatformData()V", owner: "java/lang/System", name: "getProperty", descriptor: "(Ljava/lang/String;)Ljava/lang/String;", opcode: "static" },
      ],
    };
    const report = scanSecurity([dependencyClass], [], "tr.net.nexuby.NexubyCore");
    expect(report.findings.some((finding) => finding.id.startsWith("execution"))).toBe(false);
    expect(report.score).toBe(0);
    expect(report.findings.every((finding) => finding.scope === "dependency" && finding.scoreImpact === 0)).toBe(true);
  });

  it("does not exempt malicious code merely because it lives outside the main package", () => {
    const backdoor: ParsedClass = {
      path: "evil/loader/Backdoor.class",
      name: "evil/loader/Backdoor",
      javaVersion: 65,
      methods: ["run()V"],
      byteText: "",
      calls: [
        { caller: "run()V", owner: "java/lang/Runtime", name: "exec", descriptor: "(Ljava/lang/String;)Ljava/lang/Process;", opcode: "virtual" },
      ],
    };
    const report = scanSecurity([backdoor], [], "tr.net.nexuby.NexubyCore");
    expect(report.score).toBeGreaterThanOrEqual(40);
    expect(report.level).toBe("high");
    expect(report.findings).toContainEqual(expect.objectContaining({ id: "execution", scope: "plugin", scoreImpact: 40 }));
  });

  it("never suppresses dangerous sinks hidden under a known library package", () => {
    const disguisedBackdoor: ParsedClass = {
      path: "org/bstats/Hidden.class",
      name: "org/bstats/Hidden",
      javaVersion: 65,
      methods: ["run()V"],
      byteText: "",
      calls: [
        { caller: "run()V", owner: "java/lang/Runtime", name: "exec", descriptor: "(Ljava/lang/String;)Ljava/lang/Process;", opcode: "virtual" },
      ],
    };
    const report = scanSecurity([disguisedBackdoor], [], "tr.net.nexuby.NexubyCore");
    expect(report.score).toBeGreaterThanOrEqual(40);
    expect(report.findings).toContainEqual(expect.objectContaining({ id: "execution-dependency", scope: "dependency", scoreImpact: 40 }));
  });
});
