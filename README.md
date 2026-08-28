# PluginLens

PluginLens is a local-first static inspector for Minecraft Bukkit, Spigot, Paper, Purpur, and Folia plugin JARs. It gives server owners evidence about a plugin before it reaches a live server.

Current release: **v1.0.0**.

## Privacy model

**The selected JAR never leaves the browser.** Archive reading, YAML parsing, JVM class parsing, SHA-256 calculation, and report generation all run client-side. There is no upload endpoint and no server-side JAR processing.

Network access is opt-in. PluginLens contacts the public GitHub API only after the user presses **Verify official release**. The request contains a public repository/tag lookup; it does not include the JAR or its local hash.

## What v1 analyzes

- `plugin.yml` and `paper-plugin.yml` identity, dependencies, commands, permissions, libraries, authors, and load configuration
- Archive contents, nested JARs, native libraries, executable resources, service providers, and signing metadata
- JVM class format, declared methods, and decoded invocation instructions
- Network, filesystem, process execution, reflection, class loading, native loading, environment access, bytecode manipulation, and obfuscation signals
- SHA-256 binary fingerprint
- Gradle, Maven, Git, manifest, build JDK, artifact, vendor, and version evidence
- GitHub repository discovery from descriptors, manifests, Git properties, and Maven POM files
- Public GitHub release/tag lookup and local hash comparison against GitHub's published asset digest
- Versioned JSON report export

## Important interpretation

PluginLens reports static evidence, not a malware verdict. A legitimate plugin may need network or filesystem access. An official release can still contain harmful code. Build integrity, source identity, and security risk are intentionally separate results.

## Browser safety limits

- Maximum JAR size: 128 MB
- Maximum archive entries: 100,000
- Maximum class files: 50,000

These limits reduce accidental browser memory exhaustion. They are not security guarantees.

## Development

Requirements: Node.js 22 and npm.

```bash
npm ci
npm run dev
```

Open `http://localhost:3000`.

Validation commands:

```bash
npm run typecheck
npm test
npm run build
```

`npm run check` runs all three validations. GitHub Actions runs the same verification on pushes to `main` and pull requests.

## Architecture

```text
app/                         Next.js UI
components/                  dropzone, results, release verification
lib/analyzer/metadata.ts     Bukkit/Paper descriptors
lib/analyzer/class-parser.ts JVM class structure and invocation tracing
lib/analyzer/security.ts     evidence rules and risk aggregation
lib/analyzer/build.ts        local fingerprint and build metadata
lib/analyzer/source.ts       repository discovery and tag candidates
tests/                       analyzer regression tests
```

## Current boundaries

- Static analysis does not execute plugin code.
- Obfuscation and reflection can hide behavior from static analysis.
- GitHub verification requires a public repository, matching release tag, and published SHA-256 asset digest.
- Reproducible source compilation is not part of v1.

## License

See [LICENSE](LICENSE).
