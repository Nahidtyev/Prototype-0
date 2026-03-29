import fs from "node:fs/promises";
import path from "node:path";
import type {
  FindingLocation,
  FindingSummary,
  NormalizedFindingCore,
} from "../../reporting/schema.js";
import {
  REPORT_SCHEMA_VERSION,
  REPORT_TOOL_NAME,
} from "../../reporting/schema.js";
import { buildFindingSummary } from "../../reporting/summary.js";
import type { Finding } from "../engine/findings.js";

type StaticSubtype = "dom" | "storage" | "script" | "unknown";

interface StaticReportFinding extends NormalizedFindingCore {
  category: "static";
  type: string;
  subtype: StaticSubtype;
  severity: Finding["severity"];
  title: string;
  description: string;
  source: "static";
  location?: FindingLocation | undefined;
  locationHint: string;
  filePath: string;
  line?: number;
  column?: number;
  ruleId: string;
  inlineScriptBlockIndex?: number;
  evidence?: Record<string, unknown> | undefined;
  sink?: string;
  storageKey?: string;
  storageKind?: string;
  resourceUrl?: string;
  correlationSignals?: {
    findingFamily: StaticSubtype;
    sink?: string;
    storageKind?: string;
    storageKeyToken?: string;
    resourceToken?: string;
    locationToken?: string;
  };
}

interface StaticJsonReport {
  schemaVersion: typeof REPORT_SCHEMA_VERSION;
  reportType: "static";
  metadata: {
    generatedAt: string;
    toolName: typeof REPORT_TOOL_NAME;
    target: string;
    mode: "static";
    targetPath: string;
    findingCount: number;
  };
  summary: FindingSummary;
  findings: StaticReportFinding[];
}

function buildLocationHint(finding: Finding): string {
  if (finding.line !== undefined) {
    return `${finding.filePath}:${finding.line}:${(finding.column ?? 0) + 1}`;
  }

  return finding.filePath;
}

function getInlineScriptBlockIndex(finding: Finding): number | undefined {
  return typeof finding.inlineScriptBlockIndex === "number"
    ? finding.inlineScriptBlockIndex
    : undefined;
}

function buildLocation(finding: Finding): FindingLocation {
  const location: FindingLocation = {
    path: finding.filePath,
    hint: buildLocationHint(finding),
  };

  if (finding.line !== undefined) {
    location.line = finding.line;
  }

  if (finding.column !== undefined) {
    location.column = finding.column + 1;
  }

  const inlineScriptBlockIndex = getInlineScriptBlockIndex(finding);
  if (inlineScriptBlockIndex !== undefined) {
    location.inlineScriptBlockIndex = inlineScriptBlockIndex;
  }

  return location;
}

function detectSubtype(finding: Finding): StaticSubtype {
  const text = `${finding.ruleId} ${finding.message}`.toLowerCase();

  if (
    text.includes("dom") ||
    text.includes("xss") ||
    text.includes("innerhtml") ||
    text.includes("outerhtml") ||
    text.includes("insertadjacenthtml") ||
    text.includes("document.write") ||
    text.includes("documentwrite") ||
    text.includes("eval")
  ) {
    return "dom";
  }

  if (
    text.includes("storage") ||
    text.includes("localstorage") ||
    text.includes("sessionstorage") ||
    text.includes("indexeddb") ||
    text.includes("cookie")
  ) {
    return "storage";
  }

  if (
    text.includes("script") ||
    text.includes("third-party") ||
    text.includes("third party") ||
    text.includes(".js") ||
    text.includes("http://") ||
    text.includes("https://")
  ) {
    return "script";
  }

  return "unknown";
}

function extractSink(message: string): string | undefined {
  const text = message.toLowerCase();

  if (text.includes("innerhtml")) return "innerhtml";
  if (text.includes("outerhtml")) return "outerhtml";
  if (text.includes("insertadjacenthtml")) return "insertadjacenthtml";
  if (text.includes("document.write") || text.includes("documentwrite")) return "documentwrite";
  if (text.includes("eval")) return "eval";
  if (text.includes("settimeout")) return "settimeout";
  if (text.includes("setinterval")) return "setinterval";
  if (text.includes("localstorage")) return "localstorage";
  if (text.includes("sessionstorage")) return "sessionstorage";
  if (text.includes("indexeddb")) return "indexeddb";
  if (text.includes("cookie") || text.includes("document.cookie")) return "cookie";
  if (text.includes("script src") || text.includes("setattribute('src'") || text.includes(".js")) {
    return "scriptsrcassignment";
  }

  return undefined;
}

function extractStorageKey(message: string): string | undefined {
  const patterns = [
    /setitem\s*\(\s*["'`]([a-zA-Z0-9_.:-]+)["'`]/i,
    /storage key\s*[:=]\s*["'`]([a-zA-Z0-9_.:-]+)["'`]/i,
    /key\s*[:=]\s*["'`]([a-zA-Z0-9_.:-]+)["'`]/i,
    /["'`]([a-zA-Z0-9_.:-]+)["'`]/i,
  ];

  for (const pattern of patterns) {
    const match = message.match(pattern);
    if (match?.[1]) {
      return match[1].toLowerCase();
    }
  }

  return undefined;
}

function extractResourceUrl(message: string): string | undefined {
  const match = message.match(
    /(https?:\/\/[^\s"'`)\]]+|(?:\/|\.\.\/|\.\/)[^\s"'`)\]]+\.m?js)/i,
  );

  if (!match?.[1]) {
    return undefined;
  }

  try {
    const parsed = new URL(match[1], "https://placeholder.local");
    const host = parsed.host === "placeholder.local" ? "" : parsed.host.toLowerCase();
    const pathname = parsed.pathname.replace(/\/+$/, "") || "/";
    return `${host}${pathname}`.toLowerCase();
  } catch {
    return match[1]
      .replace(/[?#].*$/, "")
      .replace(/\\/g, "/")
      .replace(/\/+$/, "")
      .toLowerCase();
  }
}

function mapType(subtype: StaticSubtype): string {
  switch (subtype) {
    case "dom":
      return "DOM_SINK_POTENTIAL";
    case "storage":
      return "BROWSER_STORAGE_USAGE";
    case "script":
      return "SCRIPT_REFERENCE";
    default:
      return "STATIC_FINDING";
  }
}

function buildTitle(finding: Finding, subtype: StaticSubtype): string {
  switch (subtype) {
    case "dom":
      return `Static DOM finding: ${finding.ruleId}`;
    case "storage":
      return `Static storage finding: ${finding.ruleId}`;
    case "script":
      return `Static script finding: ${finding.ruleId}`;
    default:
      return `Static finding: ${finding.ruleId}`;
  }
}

function toStaticReportFinding(finding: Finding): StaticReportFinding {
  const subtype = detectSubtype(finding);
  const locationHint = buildLocationHint(finding);
  const location = buildLocation(finding);
  const inlineScriptBlockIndex = getInlineScriptBlockIndex(finding);
  const sink = extractSink(finding.message);
  const storageKey =
    subtype === "storage"
      ? typeof finding.storageKey === "string"
        ? finding.storageKey.toLowerCase()
        : extractStorageKey(finding.message)
      : undefined;
  const storageKind =
    subtype === "storage" && typeof finding.storageKind === "string"
      ? finding.storageKind
      : undefined;
  const resourceUrl = subtype === "script" ? extractResourceUrl(finding.message) : undefined;

  const reportFinding: StaticReportFinding = {
    category: "static",
    type: mapType(subtype),
    subtype,
    severity: finding.severity,
    title: buildTitle(finding, subtype),
    description: finding.message,
    source: "static",
    location,
    locationHint,
    filePath: finding.filePath,
    ruleId: finding.ruleId,
    evidence: {
      ruleId: finding.ruleId,
      ...(inlineScriptBlockIndex !== undefined
        ? { inlineScriptBlockIndex }
        : {}),
      ...(sink !== undefined ? { sink } : {}),
      ...(storageKey !== undefined ? { storageKey } : {}),
      ...(storageKind !== undefined ? { storageKind } : {}),
      ...(resourceUrl !== undefined ? { resourceUrl } : {}),
    },
  };

  if (finding.line !== undefined) {
    reportFinding.line = finding.line;
  }

  if (finding.column !== undefined) {
    reportFinding.column = finding.column;
  }

  if (sink !== undefined) {
    reportFinding.sink = sink;
  }

  if (storageKey !== undefined) {
    reportFinding.storageKey = storageKey;
  }

  if (storageKind !== undefined) {
    reportFinding.storageKind = storageKind;
  }

  if (resourceUrl !== undefined) {
    reportFinding.resourceUrl = resourceUrl;
  }

  if (inlineScriptBlockIndex !== undefined) {
    reportFinding.inlineScriptBlockIndex = inlineScriptBlockIndex;
  }

  const correlationSignals: StaticReportFinding["correlationSignals"] = {
    findingFamily: subtype,
    locationToken: locationHint,
  };

  if (sink !== undefined) {
    correlationSignals.sink = sink;
  }

  if (storageKey !== undefined) {
    correlationSignals.storageKeyToken = storageKey;
  }

  if (storageKind !== undefined) {
    correlationSignals.storageKind = storageKind;
  }

  if (resourceUrl !== undefined) {
    correlationSignals.resourceToken = resourceUrl;
  }

  reportFinding.correlationSignals = correlationSignals;

  return reportFinding;
}

export async function writeStaticJsonReport(
  findings: Finding[],
  targetPath: string,
  outputPath: string,
): Promise<void> {
  const normalizedFindings = findings.map(toStaticReportFinding);
  const report: StaticJsonReport = {
    schemaVersion: REPORT_SCHEMA_VERSION,
    reportType: "static",
    metadata: {
      generatedAt: new Date().toISOString(),
      toolName: REPORT_TOOL_NAME,
      target: targetPath,
      mode: "static",
      targetPath,
      findingCount: normalizedFindings.length,
    },
    summary: buildFindingSummary(normalizedFindings),
    findings: normalizedFindings,
  };

  await fs.mkdir(path.dirname(outputPath), { recursive: true });
  await fs.writeFile(outputPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
}
