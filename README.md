# Prototype-0

## Project overview

Prototype-0 is a TypeScript prototype developed as part of the master thesis:
"Design of a Methodological Framework for Detecting Client-Side Security Vulnerabilities in Web Applications."

The project currently demonstrates a combined workflow for:

- static analysis
- dynamic browser-based analysis
- correlation of static and dynamic findings
- JSON report generation

This repository is intentionally prototype-stage. It is useful for thesis experimentation, method refinement, and MVP hardening work, but it is not production-ready.

## Current capabilities

- Static scanning of `.js`, `.jsx`, `.ts`, `.tsx`, and `.html` files, including inline JavaScript inside HTML `<script>` blocks.
- Static rules for obvious DOM XSS patterns, insecure browser storage usage, and risky third-party script loading patterns.
- Static DOM-XSS detection now also handles a small set of transformed-source cases such as `location.hash.slice(1)`, `location.hash.trim()`, one-step variable pass-through, and simple string or template wrapping of already-tainted values.
- Dynamic scanning with Playwright and Chromium, including runtime hook injection and script request observation.
- Dynamic normalization of browser events into structured findings for DOM sinks, storage writes, dynamic script activity, and external script loads.
- Correlation of static and dynamic report inputs using fingerprints and heuristic matching signals.
- JSON output for static, dynamic, and correlated results.
- Console output for static scans when no JSON output path is requested.

## Current architecture

The current repository structure is the authoritative design for this prototype:

- `src/cli.ts`: entry point that dispatches static scan, dynamic scan, and correlation commands.
- `src/static/*`: source collection, parsing, rule execution, console output, and static JSON report writing.
- `src/dynamic/*`: Playwright-driven scanning, runtime instrumentation hooks, event normalization, and dynamic JSON report writing.
- `src/correlation/*`: report loading, normalization, heuristic matching, and correlated report generation.
- `test-apps/*`: local sample targets used to exercise the prototype.
- `reports/*`: generated report examples from local runs.
- `dist/*`: compiled CLI output after build.

The current architecture already supports the core thesis workflow. The next MVP phase should evolve it incrementally rather than replace it.

## Installation / prerequisites

- Node.js and npm are required.
- Install project dependencies with `npm install`.
- Dynamic scanning depends on Playwright and browser availability on the machine.
- If Playwright browsers are not installed yet, a separate browser install step such as `npx playwright install chromium` may be required.
- Dynamic scanning also depends on the target URL being reachable at runtime.

## Build and run commands

Install dependencies:

```bash
npm install
```

Build the project:

```bash
npm run build
```

Run the TypeScript CLI directly during development:

```bash
npm run dev -- <command>
```

Run the compiled CLI after building:

```bash
npm start -- <command>
```

Config note:

- If `prototype0.config.json` exists in the current working directory, the CLI loads it automatically.
- You can override that with `--config <path>`.

## Static scan usage

Scan a directory and write a JSON report:

```bash
npm run dev -- test-apps --output reports/static-report.json
```

Use config-driven defaults:

```bash
npm run dev -- --config prototype0.config.json
```

Scan a single file:

```bash
npm run dev -- test-apps/vulnerable-react-app/App.tsx
```

Current static scan notes:

- If `--output` is omitted, findings are printed to the console.
- The scanner currently searches `js`, `jsx`, `ts`, `tsx`, and `html` files.
- For `.html` files, existing third-party-script checks still run and inline `<script>` blocks without `src` are analyzed with the same AST-based rules used for JavaScript and TypeScript files.
- `node_modules`, `dist`, `.git`, and `coverage` are ignored during directory scans.

## Dynamic scan usage

Run a dynamic scan and write a JSON report:

```bash
npm run dev -- dynamic scan --url http://localhost:8080 --output reports/dynamic-report.json
```

Use config-driven URL and output defaults:

```bash
npm run dev -- --config prototype0.config.json dynamic scan
```

Include raw captured runtime and network events:

```bash
npm run dev -- dynamic scan --url http://localhost:8080 --output reports/dynamic-report.json --include-raw
```

Run the browser with a visible window:

```bash
npm run dev -- dynamic scan --url http://localhost:8080 --headed
```

Current dynamic scan notes:

- The current implementation uses Playwright with Chromium.
- The target must already be running and reachable.
- Browser availability is a prerequisite for this command.
- The CLI examples use `dynamic scan`; the current parser also tolerates `dynamic` without the extra `scan` token.

## Correlation usage

Correlate existing static and dynamic reports:

```bash
npm run dev -- correlate --static reports/static-report.json --dynamic reports/dynamic-report.json --output reports/correlated-report.json
```

Use config-driven report paths:

```bash
npm run dev -- --config prototype0.config.json correlate
```

Current correlation notes:

- Both inputs must be JSON objects containing a `findings` array.
- If `--output` is omitted, the current default is `reports/correlated-report.json`.
- Correlation primarily relies on normalized signals such as sink names, storage keys, resource URLs, and location hints.
- Source-location proximity is now a configurable supporting heuristic through `correlation.locationDistanceThreshold`; it is not the primary match driver.

## Reports overview

The prototype currently produces three report families:

- Static report: shared top-level schema metadata, summary counts, and normalized static findings.
- Dynamic report: shared top-level schema metadata, summary counts, normalized runtime findings, and optional raw event capture.
- Correlation report: shared top-level schema metadata, summary counts, and matched/unmatched finding groups.

Current sample outputs are stored under `reports/`.

At this stage, the report family structures now share a lightweight normalized envelope, but some legacy field differences are still intentionally tolerated for compatibility.

## Test apps overview

The repository currently includes sample targets under `test-apps/`:

- `test-apps/vulnerable-react-app/`: simple source fixtures for static analysis cases such as DOM sinks, browser storage writes, and remote script loading.
- `test-apps/dynamic-lab/`: a small HTML page that can be used as a same-target end-to-end demo for static scan, dynamic scan, and correlation.
- `test-apps/html-inline-lab/`: a small HTML fixture for inline-script static analysis, including DOM sink, storage, third-party script, and parse-error cases.
- `test-apps/safe-react-app/`: currently a placeholder directory and not yet a populated benchmark sample.

These fixtures are useful for development and thesis demonstrations, but they should not be treated as a complete evaluation corpus.

## Known limitations

- The project is a prototype and is not production-ready.
- Configuration support is intentionally lightweight in the current MVP step and not all config fields are wired yet.
- Static analysis currently focuses on a limited rule set and detects only relatively direct patterns, even though small transformed-source DOM-XSS cases are now covered.
- Inline HTML script location mapping is intentionally approximate at the block-offset level; line references are more reliable than exact columns for malformed or heavily formatted inline code.
- Dynamic analysis currently performs a single browser-driven visit with a fixed post-load wait; it does not crawl, authenticate, or model complex user journeys.
- Dynamic scan coverage depends on Playwright, Chromium, and target reachability.
- Dynamic network observation currently focuses on script requests rather than a broad set of resource types.
- Correlation currently relies on heuristics and normalization rules, so false positives and false negatives are still possible.
- Report structures are more consistent than earlier versions, but legacy field variations are still tolerated in correlation inputs.
- Location normalization can differ between filesystem paths, local file URLs, and browser stack traces.
- The repository contains example reports and fixtures, but not a complete validation or benchmarking framework yet.

## MVP roadmap

The next MVP step should strengthen the current prototype without replacing its structure:

1. Stabilize report schemas and naming conventions across all report families.
2. Wire configuration loading into the CLI and scanning flow.
3. Improve correlation quality through stronger normalization and more consistent matching inputs.
4. Improve CLI flow, validation, and error handling for missing inputs and unreachable targets.
5. Expand documentation and fixture coverage so the prototype is easier to reproduce and evaluate.

## Thesis relevance

Prototype-0 operationalizes the thesis idea as a working research artifact: static analysis, dynamic analysis, and result correlation are already implemented in one repository and produce structured outputs suitable for inspection.

Its current value is methodological. It provides a concrete base for evaluating how multiple client-side detection perspectives can be combined, where the current gaps are, and what must be stabilized to reach a framework-level MVP.

## Same-target demo flow

`test-apps/dynamic-lab/index.html` is the clearest same-target demonstration page in the current repository.

On load, it intentionally:

- reads `location.hash` and assigns it to `innerHTML`
- writes a token-like value to `localStorage`
- creates a remote `<script>` element and assigns an external `src`

That lets the same target produce:

- static findings against the inline HTML script
- dynamic findings from page-load runtime behavior
- corroborated correlation output across DOM, storage, and script activity

For local use, serve `test-apps/dynamic-lab/` over HTTP and scan `http://127.0.0.1:8081/index.html` or an equivalent local URL.
