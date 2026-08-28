# PluginLens

PluginLens is a local-first inspector for Minecraft plugin JARs. It helps server owners understand plugin metadata and archive structure before the plugin reaches a server.

## Privacy first

**Your JAR is never uploaded.** The initial analysis runs entirely in the browser using the File API and JSZip. This project has no upload endpoint and no server-side JAR processing.

## v1 milestone

- Drag-and-drop `.jar` inspection interface
- Client-side JAR/ZIP reading
- `plugin.yml` and `paper-plugin.yml` metadata parsing
- Overview of name, version, main class, authors, website, and archive counts
- First-pass local security scan for network, filesystem, process-launching, reflection, and obfuscation signals
- Dependency-free JVM class-file parser with class names, class format versions, and declared method inventory
- Local SHA-256 binary fingerprint and embedded manifest/Maven/git build metadata extraction
- Modular analyzer foundation for security scanning, bytecode parsing, and build/source verification

## Getting started

```bash
npm install
npm run dev
```

Then open `http://localhost:3000` and drop in a plugin JAR.

## Roadmap

1. Method-level bytecode call tracing
2. Official release hash comparison and source/build verification
