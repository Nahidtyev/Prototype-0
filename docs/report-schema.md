# Report Schema Notes

## Why report schema consistency matters

Prototype-0 already produces machine-readable JSON outputs for static analysis, dynamic analysis, and correlation. That is a strong foundation, but schema consistency matters because the next MVP phase depends on predictable field names, stable report envelopes, and correlation inputs that mean the same thing across all stages.

Without that consistency, every downstream step has to normalize data defensively, which makes correlation harder to trust and documentation harder to keep accurate.

## Current report families

Current normalized implementation:

- All three report families now include top-level `schemaVersion`, `reportType`, `metadata`, and `summary`.
- Static and dynamic reports continue to expose a top-level `findings` array.
- Correlation reports keep their grouped result collections instead of forcing everything into a single findings list.
- The correlation reader still tolerates older static and dynamic report inputs that contain a usable top-level `findings` array even if `schemaVersion` is missing.

### Static report

Currently implemented in practice:

- Top-level `schemaVersion` and `reportType`.
- Top-level `metadata` object with `generatedAt`, `toolName`, `target`, `targetPath`, `mode`, and `findingCount`.
- Top-level `summary` object with `totalFindings`, `findingsBySeverity`, and `findingsByType`.
- Top-level `findings` array.
- Each finding now uses a more stable structure with fields such as `category`, `type`, `subtype`, `severity`, `title`, `description`, `source`, `location`, `locationHint`, `evidence`, `filePath`, `ruleId`, and optional correlation-related fields.

### Dynamic report

Currently implemented in practice:

- Top-level `schemaVersion` and `reportType`.
- Top-level `metadata` object with `generatedAt`, `toolName`, `target`, `startedAt`, `finishedAt`, `targetUrl`, `browser`, and `findingCount`.
- Top-level `summary` object with `totalFindings`, `findingsBySeverity`, `findingsByType`, `rawRuntimeEventCount`, and `rawNetworkEventCount`.
- Top-level `findings` array.
- Optional `rawEvents` object when the scan is run with `--include-raw`.
- Each finding contains normalized runtime or network evidence, including `location`, `locationHint`, correlation fingerprints, and structured evidence objects.

### Correlation report

Currently implemented in practice:

- Top-level `schemaVersion` and `reportType`.
- Top-level `metadata` object with `generatedAt`, `toolName`, optional target context, input report paths, per-input summaries, and small heuristic metadata such as `locationDistanceThreshold`.
- Top-level `summary` object with counts for corroborated, static-only, dynamic-only, ignored-static, ignored-dynamic, and corroborated families.
- Separate top-level arrays for `corroborated`, `staticOnly`, `dynamicOnly`, `ignoredStatic`, and `ignoredDynamic`.
- Each corroborated item includes a `matchSummary` with matched family, matched signals, concise reasoning text, and location-distance details when they are available.
- No single top-level `findings` array in this report family.

## Current important fields already present in practice

The following fields are already meaningful and actively used by the prototype:

- `severity`
- `type`
- `subtype`
- `title`
- `description`
- `location`
- `locationHint`
- `correlationFingerprint`
- `correlationSignals`
- `evidence`
- `summary`

These fields are especially important because correlation already depends on tokens derived from sink names, storage keys, resource URLs, and location hints. Source-location distance is now also exposed as a configurable supporting heuristic, but it does not replace the normalized content signals.

## Known inconsistencies / legacy output issues

- The top-level `metadata` shape differs across static, dynamic, and correlation reports.
- Static findings still include `filePath`, while dynamic findings usually derive richer location detail from browser stack traces and runtime evidence.
- The meaning of `source` is still not uniform: static uses `static`, while dynamic uses `runtime` or `network`.
- Correlation output does not use a shared `findings` array and instead splits results into several top-level groups.
- `locationHint` formatting can vary between filesystem paths, local file URLs, and browser-derived stack traces.
- Path case and URL encoding can differ across outputs, which is one reason the correlation layer performs additional normalization.
- Optional `rawEvents` only exists in dynamic reports.
- Experimental or older example outputs may still exist under `artifacts/`, so those files should not be treated as the stabilized schema contract.

## Proposed normalized schema direction for MVP

The following direction is proposed for MVP stabilization. It is not fully implemented yet.

- Keep the current three-stage architecture, but make all report families use a clearer common envelope.
- Add an explicit schema version to every report family, not only future config.
- Keep finding families such as `dom`, `storage`, and `script`, but normalize how location, evidence, and correlation data are represented.
- Standardize a small shared core for findings:
  - `category`
  - `type`
  - `subtype`
  - `severity`
  - `title`
  - `description`
  - `origin`
  - `location`
  - `correlation`
  - `evidence`
- Preserve correlation-specific groupings such as matched and unmatched findings, but embed consistently shaped finding objects inside those groups.

This is an incremental schema cleanup, not a redesign of the current project.

## Example JSON snippets

### Current normalized static report snippet

```json
{
  "schemaVersion": "0.2.0",
  "reportType": "static",
  "metadata": {
    "generatedAt": "2026-03-27T19:51:24.233Z",
    "toolName": "Prototype-0",
    "target": "C:\\Users\\nahid\\Downloads\\Master Thesis\\Prototype-0\\test-apps",
    "targetPath": "C:\\Users\\nahid\\Downloads\\Master Thesis\\Prototype-0\\test-apps",
    "mode": "static",
    "findingCount": 8
  },
  "summary": {
    "totalFindings": 8
  },
  "findings": [
    {
      "category": "static",
      "type": "DOM_SINK_POTENTIAL",
      "subtype": "dom",
      "severity": "HIGH",
      "title": "Static DOM finding: DOM_XSS",
      "description": "Tainted data flows into innerHTML",
      "location": {
        "path": "C:/.../App.tsx",
        "line": 4,
        "column": 1
      },
      "locationHint": "C:/.../App.tsx:4:1",
      "ruleId": "DOM_XSS"
    }
  ]
}
```

### Current normalized dynamic report snippet

```json
{
  "schemaVersion": "0.2.0",
  "reportType": "dynamic",
  "metadata": {
    "generatedAt": "2026-03-22T17:13:46.046Z",
    "toolName": "Prototype-0",
    "target": "http://localhost:8080/",
    "startedAt": "2026-03-22T17:13:43.473Z",
    "finishedAt": "2026-03-22T17:13:46.046Z",
    "targetUrl": "http://localhost:8080/",
    "browser": "chromium"
  },
  "summary": {
    "totalFindings": 1
  },
  "findings": [
    {
      "category": "dynamic",
      "type": "BROWSER_STORAGE_WRITE",
      "subtype": "storage",
      "severity": "MEDIUM",
      "title": "Browser storage write detected: localStorage.setItem",
      "description": "Runtime evidence shows a write to localStorage.setItem.",
      "source": "runtime",
      "location": {
        "hint": "/.../index.html:16:20",
        "pageUrl": "http://localhost:8080/"
      },
      "locationHint": "/.../index.html:16:20",
      "correlationFingerprint": "dynamic|storage|localstorage|token|...",
      "evidence": {
        "storageApi": "localStorage",
        "key": "token"
      }
    }
  ]
}
```

### Legacy tolerated input direction

```json
{
  "metadata": {
    "generatedAt": "2026-03-29T00:00:00.000Z"
  },
  "findings": [
    {
      "category": "static",
      "type": "DOM_SINK_POTENTIAL",
      "subtype": "dom",
      "severity": "HIGH",
      "severity": "HIGH",
      "locationHint": "test-apps/vulnerable-react-app/App.tsx:4:1"
    }
  ]
}
```

The correlation reader still accepts a legacy report like the snippet above as long as the top-level `findings` array remains available and each finding still carries the fields needed for matching.
