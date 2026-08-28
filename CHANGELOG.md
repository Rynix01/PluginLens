# Changelog

## 1.0.1 — 2026-08-29

- Match sensitive JVM capabilities at exact method level instead of broad class-name matches
- Treat `Runtime.exec` as process execution without misclassifying harmless `Runtime` inspection calls
- Separate plugin-owned code from bundled dependency evidence and exclude dependency-only signals from risk scoring
- Restrict Maven repository discovery to metadata matching the plugin name, artifact, or main class
- Show finding scope and individual score impact in the security results
- Add regressions for bStats false positives and shaded dependency repository metadata

## 1.0.0 — 2026-08-29

- Local drag-and-drop JAR analysis with browser safety limits
- Bukkit/Paper descriptor, archive, build, source, and JVM class inspection
- Method-level sensitive invocation evidence and risk scoring
- Gradle, Maven, Git, manifest, JDK, artifact, and version detection
- GitHub repository discovery and official release digest verification
- Sectioned results UI and versioned JSON report export
- Automated analyzer regression tests and GitHub Actions CI
- Next.js 16.3.3 dependency security baseline
