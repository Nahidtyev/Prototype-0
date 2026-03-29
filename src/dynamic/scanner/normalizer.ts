import type {
  CorrelationSignals,
  NormalizedFinding,
  RuntimeLocation,
} from "../types.js";
import type { FindingLocation } from "../../reporting/schema.js";

type NormalizerRuntimeEvent = {
  type: string;
  timestamp?: string | undefined;
  location?: RuntimeLocation | undefined;
  valuePreview?: string | undefined;
  url?: string | undefined;
};

type NormalizerNetworkEvent = {
  type: string;
  timestamp?: string | undefined;
  location?: RuntimeLocation | undefined;
  valuePreview?: string | undefined;
  url?: string | undefined;
};

type ParsedStackFrame = {
  raw: string;
  functionName?: string;
  url?: string;
  line?: number;
  column?: number;
};

type NormalizeInput = {
  runtimeEvents?: NormalizerRuntimeEvent[] | undefined;
  networkEvents?: NormalizerNetworkEvent[] | undefined;
  runtime?: NormalizerRuntimeEvent[] | undefined;
  network?: NormalizerNetworkEvent[] | undefined;
};

const INTERNAL_FUNCTION_NAMES = new Set([
  "getLocation",
  "patchedEval",
  "patchedWrite",
  "patchedFunction",
  "patchedSetItem",
  "patchedCreateElement",
  "patchedAppendChild",
  "patchedInsertBefore",
  "patchedSetAttribute",
  "deliverBindingResult",
  "evaluate",
]);

const INTERNAL_FRAME_SNIPPETS = [
  "__playwright__",
  "playwright",
  "utilityscript",
  "injectedscript",
  "runtimehooks",
  "storagehooks",
  "extensions::",
  "chrome-extension://",
];

function asString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 ? value : undefined;
}

function safeParseUrl(value?: string): URL | null {
  if (!value) return null;
  try {
    return new URL(value);
  } catch {
    return null;
  }
}

function normalizeIdentifier(value?: string): string {
  return (value ?? "unknown").toLowerCase().replace(/[^a-z0-9]+/g, "");
}

function normalizeLooseToken(value?: string): string {
  const result = (value ?? "unknown")
    .trim()
    .toLowerCase()
    .replace(/https?:\/\//g, "")
    .replace(/[^a-z0-9/_:.-]+/g, "");
  return result || "unknown";
}

function normalizeStorageKey(value?: string): string {
  const result = (value ?? "unknown")
    .trim()
    .toLowerCase()
    .replace(/["'`]/g, "")
    .replace(/\s+/g, "")
    .replace(/[^a-z0-9:_-]/g, "")
    .replace(/\d+/g, "#");
  return result || "unknown";
}

function normalizeResourceUrl(value?: string): string {
  if (!value) return "unknown";

  try {
    const parsed = new URL(value);
    const path = parsed.pathname
      .replace(/\d+/g, "#")
      .replace(/[a-f0-9]{8,}/gi, "#");
    return `${parsed.host}${path}`.toLowerCase();
  } catch {
    return normalizeLooseToken(value);
  }
}

function buildCorrelationFingerprint(parts: Array<string | undefined>): string {
  return parts.map((part) => (part && part.length > 0 ? part : "unknown")).join("|");
}

function extractFirstHttpUrl(value?: string): string | undefined {
  if (!value) return undefined;

  const quoted = value.match(/['"`](https?:\/\/[^'"`]+)['"`]/i);
  if (quoted?.[1]) return quoted[1];

  const bare = value.match(/https?:\/\/[^\s'"`)]+/i);
  return bare?.[0];
}

function extractStorageKeyFromPreview(value?: string): string | undefined {
  if (!value) return undefined;
  const match = value.match(/\(\s*['"`]([^'"`]+)['"`]\s*,/);
  return match?.[1];
}

function parseSingleStackLine(rawLine: string): ParsedStackFrame | null {
  const trimmed = rawLine.trim().replace(/^at\s+/, "");

  let match = trimmed.match(/^(.*?)\s+\((.*):(\d+):(\d+)\)$/);
  if (match) {
    const functionName = asString(match[1]);
    const url = asString(match[2]);

    return {
      raw: rawLine,
      ...(functionName ? { functionName } : {}),
      ...(url ? { url } : {}),
      line: Number(match[3]),
      column: Number(match[4]),
    };
  }

  match = trimmed.match(/^(.*):(\d+):(\d+)$/);
  if (match) {
    const url = asString(match[1]);

    return {
      raw: rawLine,
      ...(url ? { url } : {}),
      line: Number(match[2]),
      column: Number(match[3]),
    };
  }

  match = trimmed.match(/^(.*?)@(.*):(\d+):(\d+)$/);
  if (match) {
    const functionName = asString(match[1]);
    const url = asString(match[2]);

    return {
      raw: rawLine,
      ...(functionName ? { functionName } : {}),
      ...(url ? { url } : {}),
      line: Number(match[3]),
      column: Number(match[4]),
    };
  }

  const functionName = asString(trimmed);

  return {
    raw: rawLine,
    ...(functionName ? { functionName } : {}),
  };
}

function parseStackFrames(stack?: string): ParsedStackFrame[] {
  if (!stack) return [];
  return stack
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .map(parseSingleStackLine)
    .filter((frame): frame is ParsedStackFrame => frame !== null);
}

function isInternalFrame(frame: ParsedStackFrame): boolean {
  const fn = (frame.functionName ?? "").toLowerCase();
  const raw = `${frame.raw} ${frame.url ?? ""}`.toLowerCase();

  if (
    [...INTERNAL_FUNCTION_NAMES].some(
      (name) => fn === name.toLowerCase() || fn.endsWith(`.${name.toLowerCase()}`),
    )
  ) {
    return true;
  }

  return INTERNAL_FRAME_SNIPPETS.some((snippet) => raw.includes(snippet));
}

function isMeaningfulApplicationFrame(
  frame: ParsedStackFrame,
  location?: RuntimeLocation,
): boolean {
  if (isInternalFrame(frame)) return false;

  if (!frame.url) {
    return Boolean(frame.functionName);
  }

  if (frame.url === "<anonymous>") return false;
  if (frame.url.startsWith("http://") || frame.url.startsWith("https://")) return true;
  if (frame.url.startsWith("webpack://") || frame.url.startsWith("vite://")) return true;
  if (frame.url.includes("/src/")) return true;

  const page = safeParseUrl(location?.pageUrl);
  const frameUrl = safeParseUrl(frame.url);

  if (page && frameUrl && page.origin === frameUrl.origin) return true;

  return true;
}

function selectMeaningfulApplicationFrame(
  location?: RuntimeLocation,
): ParsedStackFrame | null {
  const frames = parseStackFrames(location?.stack);
  if (frames.length === 0) return null;

  const page = safeParseUrl(location?.pageUrl) ?? safeParseUrl(location?.frameUrl);

  if (page) {
    for (const frame of frames) {
      if (!isMeaningfulApplicationFrame(frame, location)) continue;
      const frameUrl = safeParseUrl(frame.url);
      if (frameUrl && frameUrl.origin === page.origin) {
        return frame;
      }
    }
  }

  for (const frame of frames) {
    if (isMeaningfulApplicationFrame(frame, location)) {
      return frame;
    }
  }

  return null;
}

function shortenLocationUrl(url?: string): string {
  if (!url) return "unknown";
  try {
    const parsed = new URL(url);
    return parsed.pathname || parsed.host || url;
  } catch {
    return url.replace(/^webpack:\/\//, "").replace(/^vite:\/\//, "");
  }
}

function buildLocationHint(location?: RuntimeLocation): string {
  const frame = selectMeaningfulApplicationFrame(location);

  if (frame) {
    const file = shortenLocationUrl(frame.url);
    const line = frame.line ?? 0;
    const col = frame.column ?? 0;
    const fn = frame.functionName ? ` :: ${frame.functionName}` : "";
    return `${file}:${line}:${col}${fn}`;
  }

  if (location?.frameUrl) return shortenLocationUrl(location.frameUrl);
  if (location?.pageUrl) return shortenLocationUrl(location.pageUrl);
  return "unknown";
}

function buildLocation(location?: RuntimeLocation): FindingLocation | undefined {
  const frame = selectMeaningfulApplicationFrame(location);
  const hint = buildLocationHint(location);
  const normalized: FindingLocation = {};

  if (hint !== "unknown") {
    normalized.hint = hint;
  }

  if (frame?.url) {
    normalized.path = shortenLocationUrl(frame.url);
  }

  if (frame?.line !== undefined) {
    normalized.line = frame.line;
  }

  if (frame?.column !== undefined) {
    normalized.column = frame.column;
  }

  if (frame?.functionName) {
    normalized.functionName = frame.functionName;
  }

  if (location?.pageUrl) {
    normalized.pageUrl = location.pageUrl;
  }

  if (location?.frameUrl) {
    normalized.frameUrl = location.frameUrl;
  }

  return Object.keys(normalized).length > 0 ? normalized : undefined;
}

function buildLocationToken(location?: RuntimeLocation): string {
  const frame = selectMeaningfulApplicationFrame(location);

  if (!frame) {
    return normalizeLooseToken(
      shortenLocationUrl(location?.frameUrl ?? location?.pageUrl),
    );
  }

  return [
    normalizeLooseToken(shortenLocationUrl(frame.url)),
    String(frame.line ?? 0),
    normalizeIdentifier(frame.functionName),
  ].join(":");
}

function eventText(event: NormalizerRuntimeEvent | NormalizerNetworkEvent): string {
  return [
    asString(event.type),
    asString((event as Record<string, unknown>).sink),
    asString((event as Record<string, unknown>).api),
    asString((event as Record<string, unknown>).method),
    asString((event as Record<string, unknown>).operation),
    asString((event as Record<string, unknown>).tagName),
    asString((event as Record<string, unknown>).attributeName),
    asString(event.valuePreview),
    asString(event.url),
    asString((event as Record<string, unknown>).src),
    asString((event as Record<string, unknown>).resourceType),
    asString((event as Record<string, unknown>).initiatorType),
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

function getEventUrl(event: NormalizerRuntimeEvent | NormalizerNetworkEvent): string | undefined {
  return (
    asString(event.url) ??
    asString((event as Record<string, unknown>).src) ??
    extractFirstHttpUrl(event.valuePreview)
  );
}

function isExternalResource(url?: string, location?: RuntimeLocation): boolean {
  if (!url) return false;

  const target = safeParseUrl(url);
  if (!target) return false;

  const page = safeParseUrl(location?.pageUrl) ?? safeParseUrl(location?.frameUrl);
  if (!page) return true;

  return target.origin !== page.origin;
}

function looksLikeScriptUrl(url?: string): boolean {
  if (!url) return false;

  try {
    const parsed = new URL(url);
    const path = parsed.pathname.toLowerCase();
    return (
      path.endsWith(".js") ||
      path.endsWith(".mjs") ||
      path.includes("/js/") ||
      path.includes("script")
    );
  } catch {
    const lower = url.toLowerCase();
    return lower.endsWith(".js") || lower.includes("script");
  }
}

function detectDomSink(event: NormalizerRuntimeEvent): string | null {
  const text = eventText(event);

  if (text.includes("innerhtml")) return "innerHTML";
  if (text.includes("outerhtml")) return "outerHTML";
  if (text.includes("document.write") || text.includes(" write ") || text.includes("patchedwrite")) {
    return "document.write";
  }
  if (text.includes("eval")) return "eval";
  if (text.includes("functionconstructor") || text.includes("new function") || text.includes(" function ")) {
    if (
      asString(event.type)?.toLowerCase() === "function" ||
      text.includes("functionconstructor") ||
      text.includes("new function")
    ) {
      return "Function";
    }
  }

  return null;
}

function detectStorageWrite(
  event: NormalizerRuntimeEvent,
): { api: "localStorage" | "sessionStorage"; key?: string } | null {
  const text = eventText(event);
  const rawKey =
    asString((event as Record<string, unknown>).key) ??
    extractStorageKeyFromPreview(event.valuePreview);

  if (text.includes("localstorage.setitem") || text.includes("localstorage")) {
    return rawKey
      ? { api: "localStorage", key: rawKey }
      : { api: "localStorage" };
  }

  if (text.includes("sessionstorage.setitem") || text.includes("sessionstorage")) {
    return rawKey
      ? { api: "sessionStorage", key: rawKey }
      : { api: "sessionStorage" };
  }

  return null;
}

function detectDynamicScriptCreation(event: NormalizerRuntimeEvent): boolean {
  const text = eventText(event);

  if (text.includes("createelement") && text.includes("script")) return true;
  if (text.includes("appendchild") && text.includes("script")) return true;
  if (text.includes("insertbefore") && text.includes("script")) return true;

  const tagName = asString((event as Record<string, unknown>).tagName)?.toLowerCase();
  if (tagName === "script" && (text.includes("appendchild") || text.includes("insertbefore"))) {
    return true;
  }

  return false;
}

function detectScriptSrcAssignment(event: NormalizerRuntimeEvent): boolean {
  const text = eventText(event);
  const attributeName = asString((event as Record<string, unknown>).attributeName)?.toLowerCase();

  if (text.includes("script.src")) return true;
  if (text.includes("setattribute") && text.includes("src")) return true;
  if (attributeName === "src") return true;

  return false;
}

function detectExternalScriptLoad(event: NormalizerNetworkEvent): boolean {
  const text = eventText(event);
  const url = getEventUrl(event);

  const resourceType = asString((event as Record<string, unknown>).resourceType)?.toLowerCase();
  const isScriptResource =
    resourceType === "script" || looksLikeScriptUrl(url) || text.includes("script");

  if (!isScriptResource) return false;

  return isExternalResource(url, event.location);
}

function makeBaseFinding(
  input: Pick<
    NormalizedFinding,
    "type" | "subtype" | "severity" | "title" | "description" | "source"
  > & {
    timestamp?: string | undefined;
    location?: FindingLocation | undefined;
    locationHint: string;
    correlationFingerprint: string;
    correlationSignals: CorrelationSignals;
    evidence: Record<string, unknown>;
  },
): NormalizedFinding {
  const {
    type,
    subtype,
    severity,
    title,
    description,
    source,
    timestamp,
    location,
    locationHint,
    correlationFingerprint,
    correlationSignals,
    evidence,
  } = input;

  return {
    category: "dynamic",
    type,
    subtype,
    severity,
    title,
    description,
    source,
    ...(timestamp !== undefined ? { timestamp } : {}),
    ...(location !== undefined ? { location } : {}),
    locationHint,
    correlationFingerprint,
    correlationSignals,
    evidence,
  };
}

function buildDomFinding(event: NormalizerRuntimeEvent, sinkName: string): NormalizedFinding {
  const location = buildLocation(event.location);
  const locationHint = buildLocationHint(event.location);
  const locationToken = buildLocationToken(event.location);
  const sinkToken = normalizeIdentifier(sinkName);

  return makeBaseFinding({
    type: "DOM_SINK_USAGE",
    subtype: "dom",
    severity: "HIGH",
    title: `DOM sink usage detected: ${sinkName}`,
    description: `Runtime evidence shows usage of the DOM sink "${sinkName}".`,
    source: "runtime",
    timestamp: event.timestamp,
    location,
    locationHint,
    correlationFingerprint: buildCorrelationFingerprint([
      "dynamic",
      "dom",
      sinkToken,
      locationToken,
    ]),
    correlationSignals: {
      findingFamily: "dom",
      sink: sinkToken,
      locationToken,
    },
    evidence: {
      rawType: event.type,
      sink: sinkName,
      valuePreview: event.valuePreview,
      location: event.location,
    },
  });
}

function buildStorageFinding(
  event: NormalizerRuntimeEvent,
  api: "localStorage" | "sessionStorage",
  rawKey?: string,
): NormalizedFinding {
  const location = buildLocation(event.location);
  const locationHint = buildLocationHint(event.location);
  const locationToken = buildLocationToken(event.location);
  const apiToken = normalizeIdentifier(api);
  const keyToken = normalizeStorageKey(rawKey);

  return makeBaseFinding({
    type: "BROWSER_STORAGE_WRITE",
    subtype: "storage",
    severity: "MEDIUM",
    title: `Browser storage write detected: ${api}.setItem`,
    description: `Runtime evidence shows a write to ${api}.setItem.`,
    source: "runtime",
    timestamp: event.timestamp,
    location,
    locationHint,
    correlationFingerprint: buildCorrelationFingerprint([
      "dynamic",
      "storage",
      apiToken,
      keyToken,
      locationToken,
    ]),
    correlationSignals: {
      findingFamily: "storage",
      sink: apiToken,
      locationToken,
      storageKeyToken: keyToken,
    },
    evidence: {
      rawType: event.type,
      storageApi: api,
      key: rawKey,
      valuePreview: event.valuePreview,
      location: event.location,
    },
  });
}

function buildScriptCreationFinding(event: NormalizerRuntimeEvent): NormalizedFinding {
  const location = buildLocation(event.location);
  const locationHint = buildLocationHint(event.location);
  const locationToken = buildLocationToken(event.location);

  return makeBaseFinding({
    type: "DYNAMIC_SCRIPT_CREATION",
    subtype: "script",
    severity: "MEDIUM",
    title: "Dynamic script creation detected",
    description:
      "Runtime evidence shows dynamic creation or insertion of a <script> element.",
    source: "runtime",
    timestamp: event.timestamp,
    location,
    locationHint,
    correlationFingerprint: buildCorrelationFingerprint([
      "dynamic",
      "script",
      "dynamicscriptcreation",
      locationToken,
    ]),
    correlationSignals: {
      findingFamily: "script",
      sink: "dynamicscriptcreation",
      locationToken,
    },
    evidence: {
      rawType: event.type,
      valuePreview: event.valuePreview,
      location: event.location,
    },
  });
}

function buildScriptSrcAssignmentFinding(event: NormalizerRuntimeEvent): NormalizedFinding {
  const location = buildLocation(event.location);
  const locationHint = buildLocationHint(event.location);
  const locationToken = buildLocationToken(event.location);
  const rawUrl = getEventUrl(event);
  const resourceToken = normalizeResourceUrl(rawUrl);

  return makeBaseFinding({
    type: "SCRIPT_SRC_ASSIGNMENT",
    subtype: "script",
    severity: "MEDIUM",
    title: "Script src assignment detected",
    description:
      "Runtime evidence shows assignment of a script source URL through src or setAttribute('src', ...).",
    source: "runtime",
    timestamp: event.timestamp,
    location,
    locationHint,
    correlationFingerprint: buildCorrelationFingerprint([
      "dynamic",
      "script",
      "scriptsrcassignment",
      resourceToken,
      locationToken,
    ]),
    correlationSignals: {
      findingFamily: "script",
      sink: "scriptsrcassignment",
      locationToken,
      resourceToken,
    },
    evidence: {
      rawType: event.type,
      url: rawUrl,
      valuePreview: event.valuePreview,
      location: event.location,
    },
  });
}

function buildExternalScriptLoadFinding(event: NormalizerNetworkEvent): NormalizedFinding {
  const location = buildLocation(event.location);
  const locationHint = buildLocationHint(event.location);
  const locationToken = buildLocationToken(event.location);
  const rawUrl = getEventUrl(event);
  const resourceToken = normalizeResourceUrl(rawUrl);

  return makeBaseFinding({
    type: "EXTERNAL_SCRIPT_LOAD",
    subtype: "script",
    severity: "MEDIUM",
    title: "External script load detected",
    description:
      "Network evidence shows an external script resource being requested at runtime.",
    source: "network",
    timestamp: event.timestamp,
    location,
    locationHint,
    correlationFingerprint: buildCorrelationFingerprint([
      "dynamic",
      "script",
      "externalscriptload",
      resourceToken,
      locationToken,
    ]),
    correlationSignals: {
      findingFamily: "script",
      sink: "externalscriptload",
      locationToken,
      resourceToken,
    },
    evidence: {
      rawType: event.type,
      url: rawUrl,
      resourceType: (event as Record<string, unknown>).resourceType,
      initiatorType: (event as Record<string, unknown>).initiatorType,
      location: event.location,
    },
  });
}

function parseTimestampMs(value?: string): number | null {
  if (!value) return null;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? null : ms;
}

function extractLineFromLocationHint(locationHint?: string): number | null {
  if (!locationHint) return null;

  const match = locationHint.match(/:(\d+):(\d+)(?:\s|$)/);
  if (!match) return null;

  return Number(match[1]);
}

function extractPageKey(finding: NormalizedFinding): string {
  const evidence = finding.evidence as Record<string, unknown> | undefined;
  const location =
    evidence && typeof evidence["location"] === "object" && evidence["location"] !== null
      ? (evidence["location"] as Record<string, unknown>)
      : undefined;

  const pageUrl =
    location && typeof location["pageUrl"] === "string"
      ? (location["pageUrl"] as string)
      : undefined;

  const frameUrl =
    location && typeof location["frameUrl"] === "string"
      ? (location["frameUrl"] as string)
      : undefined;

  return pageUrl ?? frameUrl ?? "unknown";
}

function dedupeNormalizedFindings(findings: NormalizedFinding[]): NormalizedFinding[] {
  const exact = new Map<string, NormalizedFinding>();

  for (const finding of findings) {
    const key = `${finding.type}|${finding.correlationFingerprint}`;
    if (!exact.has(key)) {
      exact.set(key, finding);
    }
  }

  const unique = [...exact.values()];
  const keep = new Set<number>(unique.map((_, index) => index));

  const richerScriptEvidence = unique
    .map((finding, index) => ({ finding, index }))
    .filter(
      ({ finding }) =>
        finding.correlationSignals?.findingFamily === "script" &&
        (finding.type === "SCRIPT_SRC_ASSIGNMENT" ||
          finding.type === "EXTERNAL_SCRIPT_LOAD"),
    )
    .map(({ finding, index }) => ({
      index,
      pageKey: extractPageKey(finding),
      line: extractLineFromLocationHint(finding.locationHint),
      timestampMs: parseTimestampMs(finding.timestamp),
      resourceToken: finding.correlationSignals?.resourceToken,
    }));

  unique.forEach((finding, index) => {
    if (finding.type !== "DYNAMIC_SCRIPT_CREATION") return;
    if (finding.correlationSignals?.findingFamily !== "script") return;

    const creationPageKey = extractPageKey(finding);
    const creationLine = extractLineFromLocationHint(finding.locationHint);
    const creationTimestampMs = parseTimestampMs(finding.timestamp);

    const hasNearbyRicherEvidence = richerScriptEvidence.some((candidate) => {
      if (candidate.pageKey !== creationPageKey) return false;

      const lineClose =
        creationLine !== null &&
        candidate.line !== null &&
        Math.abs(candidate.line - creationLine) <= 3;

      const timeClose =
        creationTimestampMs !== null &&
        candidate.timestampMs !== null &&
        Math.abs(candidate.timestampMs - creationTimestampMs) <= 1000;

      if (
        creationLine !== null &&
        candidate.line !== null &&
        creationTimestampMs !== null &&
        candidate.timestampMs !== null
      ) {
        return lineClose && timeClose;
      }

      if (creationLine !== null && candidate.line !== null) {
        return lineClose;
      }

      if (creationTimestampMs !== null && candidate.timestampMs !== null) {
        return timeClose;
      }

      return false;
    });

    if (hasNearbyRicherEvidence) {
      keep.delete(index);
    }
  });

  return unique.filter((_, index) => keep.has(index));
}

function normalizeRuntimeEvents(runtimeEvents: NormalizerRuntimeEvent[]): NormalizedFinding[] {
  const findings: NormalizedFinding[] = [];

  for (const event of runtimeEvents) {
    const domSink = detectDomSink(event);
    if (domSink) {
      findings.push(buildDomFinding(event, domSink));
      continue;
    }

    const storage = detectStorageWrite(event);
    if (storage) {
      findings.push(buildStorageFinding(event, storage.api, storage.key));
      continue;
    }

    if (detectScriptSrcAssignment(event)) {
      findings.push(buildScriptSrcAssignmentFinding(event));
      continue;
    }

    if (detectDynamicScriptCreation(event)) {
      findings.push(buildScriptCreationFinding(event));
    }
  }

  return findings;
}

function normalizeNetworkEvents(networkEvents: NormalizerNetworkEvent[]): NormalizedFinding[] {
  const findings: NormalizedFinding[] = [];

  for (const event of networkEvents) {
    if (detectExternalScriptLoad(event)) {
      findings.push(buildExternalScriptLoadFinding(event));
    }
  }

  return findings;
}

export function normalizeDynamicFindings(
  input: NormalizeInput | NormalizerRuntimeEvent[] = [],
  maybeNetworkEvents: NormalizerNetworkEvent[] = [],
): NormalizedFinding[] {
  const runtimeEvents = Array.isArray(input)
    ? input
    : input.runtimeEvents ?? input.runtime ?? [];

  const networkEvents = Array.isArray(input)
    ? maybeNetworkEvents
    : input.networkEvents ?? input.network ?? [];

  const findings = [
    ...normalizeRuntimeEvents(runtimeEvents),
    ...normalizeNetworkEvents(networkEvents),
  ];

  return dedupeNormalizedFindings(findings);
}

export {
  normalizeDynamicFindings as normalizeDynamicEvents,
  normalizeDynamicFindings as normalizeRuntimeFindings,
  normalizeDynamicFindings as normalizeRuntimeAndNetworkEvents,
};

export default normalizeDynamicFindings;
