# Usage Examples

The examples below reflect the current CLI behavior in this repository. They assume commands are run from the project root.

## Build

Install dependencies:

```bash
npm install
```

Compile the project:

```bash
npm run build
```

Run the compiled CLI after building:

```bash
npm start -- <command>
```

If `prototype0.config.json` exists in the current working directory, it is loaded automatically. You can also point to a specific config file with `--config <path>`.

## Static scan example

Scan the `test-apps` directory and write a static JSON report:

```bash
npm run dev -- test-apps --output reports/static-report.json
```

If `--output` is omitted, the current CLI prints findings to the console instead of writing JSON:

```bash
npm run dev -- test-apps
```

Use config defaults for target paths, enabled rules, extensions, and output:

```bash
npm run dev -- --config prototype0.config.json
```

Scan an HTML file and analyze inline JavaScript inside local `<script>` blocks:

```bash
npm run dev -- test-apps/html-inline-lab/index.html --output reports/static-report.json
```

The current static scanner still performs HTML third-party-script checks and now also runs the existing JavaScript rules on inline `<script>` blocks that do not use `src`.

## Dynamic scan example

Run a dynamic scan against a reachable local target:

```bash
npm run dev -- dynamic scan --url http://localhost:8080 --output reports/dynamic-report.json
```

Include raw runtime and network events:

```bash
npm run dev -- dynamic scan --url http://localhost:8080 --output reports/dynamic-report.json --include-raw
```

Open the browser window during the run:

```bash
npm run dev -- dynamic scan --url http://localhost:8080 --headed
```

Use config defaults for URL, browser, wait time, and output:

```bash
npm run dev -- --config prototype0.config.json dynamic scan
```

## Correlation example

Correlate the previously generated reports:

```bash
npm run dev -- correlate --static reports/static-report.json --dynamic reports/dynamic-report.json --output reports/correlated-report.json
```

The current correlation command defaults to `reports/correlated-report.json` when `--output` is not supplied:

```bash
npm run dev -- correlate --static reports/static-report.json --dynamic reports/dynamic-report.json
```

Use config-derived static, dynamic, and correlated report paths:

```bash
npm run dev -- --config prototype0.config.json correlate
```

The current correlator primarily matches on normalized content signals. `correlation.locationDistanceThreshold` acts only as a supporting source-location heuristic and is read from config when present.

## Same-target demo flow

One simple end-to-end demo uses `test-apps/dynamic-lab/index.html` for both static and dynamic analysis.

Example local server command:

```bash
python -m http.server 8081 --directory test-apps/dynamic-lab
```

Run the static scan against the same file the browser will load:

```bash
npm run dev -- test-apps/dynamic-lab/index.html --output reports/dynamic-lab.static.json
```

Run the dynamic scan against the served page:

```bash
npm run dev -- dynamic scan --url http://127.0.0.1:8081/index.html --output reports/dynamic-lab.dynamic.json
```

Correlate the two reports:

```bash
npm run dev -- correlate --static reports/dynamic-lab.static.json --dynamic reports/dynamic-lab.dynamic.json --output reports/dynamic-lab.correlated.json
```

Expected result at a high level:

- static findings for an inline DOM sink, a browser-storage write, and a remote script reference
- dynamic findings for the same page-load behaviors
- corroborated correlation output for at least part of the DOM, storage, and script activity

## Example local server note for dynamic testing

Assumption for the dynamic examples:

- A local server is already serving the target page at `http://localhost:8080/`.
- The current CLI does not start or manage that server.
- Any equivalent local HTTP server is acceptable.
- Playwright and a usable Chromium browser environment must be available on the machine.

For very small local experiments, a `file:///...` target may work, but an HTTP-served page is the more representative setup for dynamic testing.

## Example output file paths

The current repository layout already uses these example output locations:

- `reports/static-report.json`
- `reports/dynamic-report.json`
- `reports/correlated-report.json`

When `--include-raw` is used for dynamic scanning, the raw event payload is embedded in the same dynamic report file rather than written to a separate file.
