import {
  REPORT_SCHEMA_VERSION,
  REPORT_TOOL_NAME,
} from '../reporting/schema.js';
import type {
  CorrelatedReport,
  CorrelationInputSummary,
  CorrelationFamily,
  CorrelationMode,
  CorrelationReportSummary,
  CorrelationScopeFamily,
  CorroboratedFinding,
  FindingReport,
  NormalizedFinding,
  ReportFinding,
  UnmatchedFinding,
} from './types.js';
import {
  DEFAULT_LOCATION_DISTANCE_THRESHOLD,
  type CorrelatorOptions,
} from './types.js';

interface CandidatePair {
  staticIndex: number;
  dynamicIndex: number;
  score: number;
  locationDistance?: number;
}

const DOM_SINKS = [
  'innerhtml',
  'outerhtml',
  'insertadjacenthtml',
  'document.write',
  'eval',
  'function',
  'settimeout',
  'setinterval',
] as const;

const STORAGE_KINDS = [
  'localstorage',
  'sessionstorage',
  'indexeddb',
  'cookie',
] as const;

function asString(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim().length > 0 ? value.trim() : undefined;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : undefined;
}

function asNumber(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

function normalizeToken(value: string | undefined): string | undefined {
  if (!value) {
    return undefined;
  }

  const normalized = value.trim().toLowerCase().replace(/\s+/g, ' ');
  return normalized.length > 0 ? normalized : undefined;
}

function normalizeSinkToken(value: string | undefined): string | undefined {
  const token = normalizeToken(value);
  if (!token) {
    return undefined;
  }

  switch (token.replace(/[^a-z0-9]+/g, '')) {
    case 'innerhtml':
      return 'innerhtml';
    case 'outerhtml':
      return 'outerhtml';
    case 'insertadjacenthtml':
      return 'insertadjacenthtml';
    case 'documentwrite':
      return 'documentwrite';
    case 'eval':
      return 'eval';
    case 'function':
      return 'function';
    case 'settimeout':
      return 'settimeout';
    case 'setinterval':
      return 'setinterval';
    default:
      return undefined;
  }
}

function normalizeStorageKindToken(value: string | undefined): string | undefined {
  const token = normalizeToken(value);
  if (!token) {
    return undefined;
  }

  if (token.includes('localstorage')) return 'localstorage';
  if (token.includes('sessionstorage')) return 'sessionstorage';
  if (token.includes('indexeddb')) return 'indexeddb';
  if (token.includes('document.cookie') || token.includes('cookie')) return 'cookie';

  return undefined;
}

function normalizeLocationToken(value: string | undefined): string | undefined {
  const token = normalizeToken(value);
  if (!token) {
    return undefined;
  }

  return token.replace(/\\/g, '/');
}

function normalizeResourceToken(value: string | undefined): string | undefined {
  if (!value) {
    return undefined;
  }

  const trimmed = value.trim();

  try {
    const parsed = new URL(trimmed, 'https://placeholder.local');
    const host = parsed.host === 'placeholder.local' ? '' : parsed.host.toLowerCase();
    const pathname = parsed.pathname.replace(/\/+$/, '') || '/';
    return normalizeToken(`${host}${pathname}`);
  } catch {
    return normalizeToken(
      trimmed
        .replace(/[?#].*$/, '')
        .replace(/\\/g, '/')
        .replace(/\/+$/, ''),
    );
  }
}

function collectText(finding: ReportFinding): string {
  const parts = [
    asString(finding.type),
    asString(finding.subtype),
    asString(finding.title),
    asString(finding.description),
    asString(finding.source),
    asString(finding.sink),
    asString(finding.storageKey),
    asString(finding.storageKind),
    asString(finding.resourceUrl),
    asString(finding.scriptUrl),
    asString(finding.url),
    asString(finding.src),
  ].filter((value): value is string => value !== undefined);

  return parts.join(' ').toLowerCase();
}

function determineFamily(finding: ReportFinding): CorrelationFamily {
  const sinkToken = extractSinkToken(finding);
  if (sinkToken) {
    return 'dom';
  }

  const storageKind = extractStorageKind(finding);
  const storageKeyToken = extractStorageKeyToken(finding);
  if (storageKind || storageKeyToken) {
    return 'storage';
  }

  const resourceToken = extractResourceToken(finding);
  if (resourceToken) {
    return 'script';
  }

  const text = collectText(finding);

  if (text.includes('dom') || text.includes('xss')) {
    return 'dom';
  }

  if (
    text.includes('storage') ||
    text.includes('localstorage') ||
    text.includes('sessionstorage') ||
    text.includes('indexeddb') ||
    text.includes('cookie')
  ) {
    return 'storage';
  }

  if (
    text.includes('third-party') ||
    text.includes('third party') ||
    text.includes('external script') ||
    text.includes('script src') ||
    text.includes('remote script') ||
    text.includes('script integrity') ||
    (text.includes('script') &&
      (text.includes('http://') || text.includes('https://') || text.includes('.js')))
  ) {
    return 'script';
  }

  return 'unknown';
}

function extractSinkToken(finding: ReportFinding): string | undefined {
  const directSink = normalizeSinkToken(asString(finding.sink));
  if (directSink) {
    return directSink;
  }

  const correlationSignals = asRecord(finding.correlationSignals);
  const evidence = asRecord(finding.evidence);
  const nestedSink =
    normalizeSinkToken(asString(correlationSignals?.sink)) ??
    normalizeSinkToken(asString(evidence?.sink));

  if (nestedSink) {
    return nestedSink;
  }

  const text = collectText(finding);

  if (text.includes('innerhtml')) return 'innerhtml';
  if (text.includes('outerhtml')) return 'outerhtml';
  if (text.includes('insertadjacenthtml')) return 'insertadjacenthtml';
  if (text.includes('document.write') || text.includes('documentwrite')) return 'documentwrite';
  if (text.includes('eval')) return 'eval';
  if (text.includes('function')) return 'function';
  if (text.includes('settimeout')) return 'settimeout';
  if (text.includes('setinterval')) return 'setinterval';

  for (const sink of DOM_SINKS) {
    if (text.includes(sink)) {
      return normalizeSinkToken(sink);
    }
  }

  return undefined;
}

function extractStorageKind(finding: ReportFinding): string | undefined {
  const correlationSignals = asRecord(finding.correlationSignals);
  const evidence = asRecord(finding.evidence);
  const direct =
    normalizeStorageKindToken(asString(finding.storageKind)) ??
    normalizeStorageKindToken(asString(correlationSignals?.storageKind)) ??
    normalizeStorageKindToken(asString(correlationSignals?.storageApi)) ??
    normalizeStorageKindToken(asString(evidence?.storageKind)) ??
    normalizeStorageKindToken(asString(evidence?.storageApi)) ??
    normalizeStorageKindToken(asString(evidence?.api)) ??
    normalizeStorageKindToken(asString(correlationSignals?.sink));

  if (direct) {
    return direct;
  }

  const text = collectText(finding);
  const textStorageKind = normalizeStorageKindToken(text);
  if (textStorageKind) {
    return textStorageKind;
  }

  for (const kind of STORAGE_KINDS) {
    if (text.includes(kind)) {
      return kind;
    }
  }

  return undefined;
}

function extractStorageKeyToken(finding: ReportFinding): string | undefined {
  const directKey = normalizeToken(asString(finding.storageKey));
  if (directKey) {
    return directKey;
  }

  const correlationSignals = asRecord(finding.correlationSignals);
  const evidence = asRecord(finding.evidence);
  const nestedKey =
    normalizeToken(asString(correlationSignals?.storageKeyToken)) ??
    normalizeToken(asString(evidence?.key)) ??
    normalizeToken(asString(finding.key));

  if (nestedKey) {
    return nestedKey;
  }

  const candidates = [
    asString(finding.title),
    asString(finding.description),
  ].filter((value): value is string => value !== undefined);

  const keyRegex = /(?:storage key|key)\s*[:=]\s*["'`]?([a-zA-Z0-9_.:-]+)["'`]?/i;

  for (const candidate of candidates) {
    const match = candidate.match(keyRegex);
    if (match?.[1]) {
      return normalizeToken(match[1]);
    }
  }

  return undefined;
}

function extractResourceToken(finding: ReportFinding): string | undefined {
  const correlationSignals = asRecord(finding.correlationSignals);
  const evidence = asRecord(finding.evidence);
  const nestedResource =
    normalizeToken(asString(correlationSignals?.resourceToken)) ??
    normalizeResourceToken(asString(evidence?.url));

  if (nestedResource) {
    return nestedResource;
  }

  const direct =
    normalizeResourceToken(asString(finding.resourceUrl)) ??
    normalizeResourceToken(asString(finding.scriptUrl)) ??
    normalizeResourceToken(asString(finding.url)) ??
    normalizeResourceToken(asString(finding.src));

  if (direct) {
    return direct;
  }

  const textCandidates = [
    asString(finding.title),
    asString(finding.description),
  ].filter((value): value is string => value !== undefined);

  const urlRegex = /(https?:\/\/[^\s"'`)\]]+|(?:\/|\.\.\/|\.\/)[^\s"'`)\]]+\.m?js)/i;

  for (const candidate of textCandidates) {
    const match = candidate.match(urlRegex);
    if (match?.[1]) {
      return normalizeResourceToken(match[1]);
    }
  }

  return undefined;
}

function extractLocationToken(finding: ReportFinding): string | undefined {
  return (
    normalizeLocationToken(asString(finding.locationHint)) ??
    normalizeLocationToken(asString(finding.location)) ??
    normalizeLocationToken(locationObjectToToken(finding.location)) ??
    normalizeLocationToken(asString(finding['file'])) ??
    normalizeLocationToken(asString(finding['filePath'])) ??
    normalizeLocationToken(asString(finding['path']))
  );
}

function locationObjectToToken(value: unknown): string | undefined {
  const record = asRecord(value);

  if (!record) {
    return undefined;
  }

  const hint = asString(record.hint);
  if (hint) {
    return hint;
  }

  const path = asString(record.path);
  const line = asNumber(record.line);
  const column = asNumber(record.column);

  if (!path) {
    return undefined;
  }

  if (line !== undefined && column !== undefined) {
    return `${path}:${line}:${column}`;
  }

  if (line !== undefined) {
    return `${path}:${line}`;
  }

  return path;
}

function parseLocation(
  locationToken: string | undefined,
): { path?: string; line?: number; column?: number } {
  if (!locationToken) {
    return {};
  }

  const match = locationToken.match(/^(.*?)(?::(\d+))(?::(\d+))?(?:\s+::.*)?$/);
  if (!match) {
    return { path: locationToken };
  }

  const result: { path?: string; line?: number; column?: number } = {};

  if (match[1]) {
    result.path = match[1];
  }

  if (match[2]) {
    result.line = Number(match[2]);
  }

  if (match[3]) {
    result.column = Number(match[3]);
  }

  return result;
}

function pathsAreComparable(leftPath: string | undefined, rightPath: string | undefined): boolean {
  if (!leftPath || !rightPath) {
    return false;
  }

  const leftBase = basename(leftPath);
  const rightBase = basename(rightPath);

  return (
    leftPath === rightPath ||
    leftPath.endsWith(rightPath) ||
    rightPath.endsWith(leftPath) ||
    (leftBase !== undefined && rightBase !== undefined && leftBase === rightBase)
  );
}

function basename(input: string | undefined): string | undefined {
  if (!input) {
    return undefined;
  }

  const normalized = input.replace(/\\/g, '/');
  const parts = normalized.split('/');
  return parts.length > 0 ? parts[parts.length - 1] : normalized;
}

function parseLocationObject(
  value: unknown,
): { path?: string; line?: number; column?: number } {
  const record = asRecord(value);

  if (!record) {
    return {};
  }

  const hintLocation = parseLocation(asString(record.hint));
  const path = asString(record.path) ?? hintLocation.path;
  const line = asNumber(record.line) ?? hintLocation.line;
  const column = asNumber(record.column) ?? hintLocation.column;

  return {
    ...(path !== undefined ? { path } : {}),
    ...(line !== undefined ? { line } : {}),
    ...(column !== undefined ? { column } : {}),
  };
}

function extractFindingLocation(
  finding: ReportFinding,
): { path?: string; line?: number; column?: number } {
  const objectLocation = parseLocationObject(finding.location);
  const hintLocation = parseLocation(asString(finding.locationHint));
  const legacyPath =
    asString(finding['file']) ??
    asString(finding['filePath']) ??
    asString(finding['path']);
  const legacyLine = asNumber(finding['line']);
  const legacyColumn = asNumber(finding['column']);

  const path = objectLocation.path ?? legacyPath ?? hintLocation.path;
  const line = objectLocation.line ?? legacyLine ?? hintLocation.line;
  const column = objectLocation.column ?? legacyColumn ?? hintLocation.column;

  return {
    ...(path !== undefined ? { path } : {}),
    ...(line !== undefined ? { line } : {}),
    ...(column !== undefined ? { column } : {}),
  };
}

function getLocationDistance(
  staticFinding: ReportFinding,
  dynamicFinding: ReportFinding,
): number | undefined {
  const left = extractFindingLocation(staticFinding);
  const right = extractFindingLocation(dynamicFinding);

  if (left.line === undefined || right.line === undefined) {
    return undefined;
  }

  const leftPath = normalizeLocationToken(left.path);
  const rightPath = normalizeLocationToken(right.path);

  if (!pathsAreComparable(leftPath, rightPath)) {
    return undefined;
  }

  return Math.abs(left.line - right.line);
}

function isWithinLocationThreshold(
  locationDistance: number | undefined,
  locationDistanceThreshold: number,
): boolean {
  return (
    locationDistance !== undefined &&
    locationDistance <= locationDistanceThreshold
  );
}

function normalizeFinding(
  finding: ReportFinding,
  index: number,
  mode: CorrelationMode,
): NormalizedFinding {
  const normalized: NormalizedFinding = {
    index,
    mode,
    family: determineFamily(finding),
    finding,
  };

  const correlationFingerprint = normalizeToken(asString(finding.correlationFingerprint));
  const sinkToken = extractSinkToken(finding);
  const storageKeyToken = extractStorageKeyToken(finding);
  const storageKind = extractStorageKind(finding);
  const resourceToken = extractResourceToken(finding);
  const locationToken = extractLocationToken(finding);
  const typeToken = normalizeToken(asString(finding.type) ?? asString(finding.subtype));
  const titleToken = normalizeToken(asString(finding.title));

  if (correlationFingerprint !== undefined) {
    normalized.correlationFingerprint = correlationFingerprint;
  }

  if (sinkToken !== undefined) {
    normalized.sinkToken = sinkToken;
  }

  if (storageKeyToken !== undefined) {
    normalized.storageKeyToken = storageKeyToken;
  }

  if (storageKind !== undefined) {
    normalized.storageKind = storageKind;
  }

  if (resourceToken !== undefined) {
    normalized.resourceToken = resourceToken;
  }

  if (locationToken !== undefined) {
    normalized.locationToken = locationToken;
  }

  if (typeToken !== undefined) {
    normalized.typeToken = typeToken;
  }

  if (titleToken !== undefined) {
    normalized.titleToken = titleToken;
  }

  return normalized;
}

function isScopedFamily(family: CorrelationFamily): family is CorrelationScopeFamily {
  return family === 'dom' || family === 'storage' || family === 'script';
}

function thresholdForFamily(family: CorrelationScopeFamily): number {
  switch (family) {
    case 'dom':
      return 70;
    case 'storage':
      return 75;
    case 'script':
      return 100;
    default: {
      const exhaustiveCheck: never = family;
      throw new Error(`Unhandled correlation family: ${String(exhaustiveCheck)}`);
    }
  }
}

function scorePair(
  staticFinding: NormalizedFinding,
  dynamicFinding: NormalizedFinding,
  locationDistanceThreshold: number,
): { score: number; locationDistance?: number } {
  if (!isScopedFamily(staticFinding.family) || !isScopedFamily(dynamicFinding.family)) {
    return { score: 0 };
  }

  if (staticFinding.family !== dynamicFinding.family) {
    return { score: 0 };
  }

  const locationDistance = getLocationDistance(
    staticFinding.finding,
    dynamicFinding.finding,
  );

  if (
    staticFinding.correlationFingerprint &&
    dynamicFinding.correlationFingerprint &&
    staticFinding.correlationFingerprint === dynamicFinding.correlationFingerprint
  ) {
    return { score: 100, ...(locationDistance !== undefined ? { locationDistance } : {}) };
  }

  switch (staticFinding.family) {
    case 'script': {
      if (
        staticFinding.resourceToken &&
        dynamicFinding.resourceToken &&
        staticFinding.resourceToken === dynamicFinding.resourceToken
      ) {
        return { score: 100, ...(locationDistance !== undefined ? { locationDistance } : {}) };
      }

      return { score: 0, ...(locationDistance !== undefined ? { locationDistance } : {}) };
    }

    case 'dom': {
      let score = 0;

      if (
        staticFinding.sinkToken &&
        dynamicFinding.sinkToken &&
        staticFinding.sinkToken === dynamicFinding.sinkToken
      ) {
        score += 70;
      }

      if (
        staticFinding.typeToken &&
        dynamicFinding.typeToken &&
        staticFinding.typeToken === dynamicFinding.typeToken
      ) {
        score += 5;
      }

      if (
        staticFinding.titleToken &&
        dynamicFinding.titleToken &&
        staticFinding.titleToken === dynamicFinding.titleToken
      ) {
        score += 5;
      }

      if (
        staticFinding.resourceToken &&
        dynamicFinding.resourceToken &&
        staticFinding.resourceToken === dynamicFinding.resourceToken
      ) {
        score += 5;
      }

      if (isWithinLocationThreshold(locationDistance, locationDistanceThreshold)) {
        score += 10;
      }

      return { score, ...(locationDistance !== undefined ? { locationDistance } : {}) };
    }

    case 'storage': {
      let score = 0;

      if (
        staticFinding.storageKeyToken &&
        dynamicFinding.storageKeyToken &&
        staticFinding.storageKeyToken === dynamicFinding.storageKeyToken
      ) {
        score += 50;
      }

      if (
        staticFinding.storageKind &&
        dynamicFinding.storageKind &&
        staticFinding.storageKind === dynamicFinding.storageKind
      ) {
        score += 30;
      }

      if (
        staticFinding.typeToken &&
        dynamicFinding.typeToken &&
        staticFinding.typeToken === dynamicFinding.typeToken
      ) {
        score += 5;
      }

      if (
        staticFinding.titleToken &&
        dynamicFinding.titleToken &&
        staticFinding.titleToken === dynamicFinding.titleToken
      ) {
        score += 5;
      }

      if (isWithinLocationThreshold(locationDistance, locationDistanceThreshold)) {
        score += 10;
      }

      return { score, ...(locationDistance !== undefined ? { locationDistance } : {}) };
    }

    default:
      return { score: 0, ...(locationDistance !== undefined ? { locationDistance } : {}) };
  }
}

function toUnmatchedFinding(finding: NormalizedFinding): UnmatchedFinding {
  const normalizedSignals: UnmatchedFinding['normalizedSignals'] = {};

  if (finding.correlationFingerprint !== undefined) {
    normalizedSignals.correlationFingerprint = finding.correlationFingerprint;
  }

  if (finding.sinkToken !== undefined) {
    normalizedSignals.sinkToken = finding.sinkToken;
  }

  if (finding.storageKeyToken !== undefined) {
    normalizedSignals.storageKeyToken = finding.storageKeyToken;
  }

  if (finding.storageKind !== undefined) {
    normalizedSignals.storageKind = finding.storageKind;
  }

  if (finding.resourceToken !== undefined) {
    normalizedSignals.resourceToken = finding.resourceToken;
  }

  if (finding.locationToken !== undefined) {
    normalizedSignals.locationToken = finding.locationToken;
  }

  return {
    family: finding.family,
    normalizedSignals,
    finding: finding.finding,
  };
}

function buildMatchReasoning(
  family: CorrelationScopeFamily,
  matchedSignals: string[],
  locationDistance: number | undefined,
  locationDistanceThreshold: number,
): string {
  const signalText =
    matchedSignals.length > 0 ? matchedSignals.join(', ') : 'compatible-normalized-signals';

  if (locationDistance === undefined) {
    return `Matched on family "${family}"; signals: ${signalText}.`;
  }

  if (locationDistance <= locationDistanceThreshold) {
    return `Matched on family "${family}"; signals: ${signalText}; line distance ${locationDistance} (threshold ${locationDistanceThreshold}).`;
  }

  return `Matched on family "${family}"; signals: ${signalText}; line distance ${locationDistance} exceeds threshold ${locationDistanceThreshold}.`;
}

function toCorroboratedFinding(
  staticFinding: NormalizedFinding & { family: CorrelationScopeFamily },
  dynamicFinding: NormalizedFinding & { family: CorrelationScopeFamily },
  score: number,
  locationDistanceThreshold: number,
  locationDistance: number | undefined,
): CorroboratedFinding {
  const matchSignals: CorroboratedFinding['matchSignals'] = {};

  if (staticFinding.locationToken !== undefined) {
    matchSignals.staticLocation = staticFinding.locationToken;
  }

  if (dynamicFinding.locationToken !== undefined) {
    matchSignals.dynamicLocation = dynamicFinding.locationToken;
  }

  let matchKind: 'fingerprint' | 'signal' = 'signal';

  if (
    staticFinding.correlationFingerprint &&
    dynamicFinding.correlationFingerprint &&
    staticFinding.correlationFingerprint === dynamicFinding.correlationFingerprint
  ) {
    matchSignals.correlationFingerprint = staticFinding.correlationFingerprint;
    matchKind = 'fingerprint';
  }

  if (
    staticFinding.sinkToken &&
    dynamicFinding.sinkToken &&
    staticFinding.sinkToken === dynamicFinding.sinkToken
  ) {
    matchSignals.sinkToken = staticFinding.sinkToken;
  }

  if (
    staticFinding.storageKeyToken &&
    dynamicFinding.storageKeyToken &&
    staticFinding.storageKeyToken === dynamicFinding.storageKeyToken
  ) {
    matchSignals.storageKeyToken = staticFinding.storageKeyToken;
  }

  if (
    staticFinding.storageKind &&
    dynamicFinding.storageKind &&
    staticFinding.storageKind === dynamicFinding.storageKind
  ) {
    matchSignals.storageKind = staticFinding.storageKind;
  }

  if (
    staticFinding.resourceToken &&
    dynamicFinding.resourceToken &&
    staticFinding.resourceToken === dynamicFinding.resourceToken
  ) {
    matchSignals.resourceToken = staticFinding.resourceToken;
  }

  const matchedSignals = [
    ...(matchSignals.correlationFingerprint !== undefined ? ['correlation-fingerprint'] : []),
    ...(matchSignals.sinkToken !== undefined ? ['sink-token'] : []),
    ...(matchSignals.storageKeyToken !== undefined ? ['storage-key-token'] : []),
    ...(matchSignals.storageKind !== undefined ? ['storage-kind'] : []),
    ...(matchSignals.resourceToken !== undefined ? ['resource-token'] : []),
    ...(isWithinLocationThreshold(locationDistance, locationDistanceThreshold)
      ? ['location-proximity']
      : []),
  ];

  return {
    family: staticFinding.family,
    score,
    matchKind,
    matchSignals,
    matchSummary: {
      matchedFamily: staticFinding.family,
      matchedSignals,
      score,
      matchKind,
      ...(locationDistance !== undefined ? { locationDistance } : {}),
      locationThresholdUsed: locationDistanceThreshold,
      reasoning: buildMatchReasoning(
        staticFinding.family,
        matchedSignals,
        locationDistance,
        locationDistanceThreshold,
      ),
    },
    staticFinding: staticFinding.finding,
    dynamicFinding: dynamicFinding.finding,
  };
}

function summarizeInputReport(
  report: FindingReport,
  scopedCount: number,
  ignoredCount: number,
): CorrelationInputSummary {
  return {
    ...(typeof report.reportType === 'string' ? { reportType: report.reportType } : {}),
    ...(typeof report.schemaVersion === 'string'
      ? { schemaVersion: report.schemaVersion }
      : {}),
    findingCount: report.findings.length,
    scopedCount,
    ignoredCount,
  };
}

function buildCorrelationSummary(
  corroborated: readonly CorroboratedFinding[],
  staticOnly: readonly UnmatchedFinding[],
  dynamicOnly: readonly UnmatchedFinding[],
  ignoredStatic: readonly UnmatchedFinding[],
  ignoredDynamic: readonly UnmatchedFinding[],
): CorrelationReportSummary {
  const corroboratedByFamily: Partial<Record<CorrelationScopeFamily, number>> = {};

  for (const finding of corroborated) {
    corroboratedByFamily[finding.family] =
      (corroboratedByFamily[finding.family] ?? 0) + 1;
  }

  return {
    corroboratedCount: corroborated.length,
    corroboratedByFamily,
    staticOnlyCount: staticOnly.length,
    dynamicOnlyCount: dynamicOnly.length,
    ignoredStaticCount: ignoredStatic.length,
    ignoredDynamicCount: ignoredDynamic.length,
  };
}

function extractReportTarget(report: FindingReport): string | undefined {
  const metadata = asRecord(report.metadata);

  return (
    asString(metadata?.target) ??
    asString(metadata?.targetPath) ??
    asString(metadata?.targetUrl)
  );
}

function buildCorrelationTarget(
  staticReport: FindingReport,
  dynamicReport: FindingReport,
): string | undefined {
  const staticTarget = extractReportTarget(staticReport);
  const dynamicTarget = extractReportTarget(dynamicReport);

  if (staticTarget && dynamicTarget) {
    return `${staticTarget} <> ${dynamicTarget}`;
  }

  return staticTarget ?? dynamicTarget;
}

export function correlateReports(
  staticReport: FindingReport,
  dynamicReport: FindingReport,
  options: CorrelatorOptions = {},
): CorrelatedReport {
  const locationDistanceThreshold =
    options.locationDistanceThreshold ?? DEFAULT_LOCATION_DISTANCE_THRESHOLD;

  const normalizedStatic: NormalizedFinding[] = staticReport.findings.map(
    (finding: ReportFinding, index: number): NormalizedFinding =>
      normalizeFinding(finding, index, 'static'),
  );

  const normalizedDynamic: NormalizedFinding[] = dynamicReport.findings.map(
    (finding: ReportFinding, index: number): NormalizedFinding =>
      normalizeFinding(finding, index, 'dynamic'),
  );

  const scopedStatic = normalizedStatic.filter(
    (
      finding: NormalizedFinding,
    ): finding is NormalizedFinding & { family: CorrelationScopeFamily } =>
      isScopedFamily(finding.family),
  );

  const scopedDynamic = normalizedDynamic.filter(
    (
      finding: NormalizedFinding,
    ): finding is NormalizedFinding & { family: CorrelationScopeFamily } =>
      isScopedFamily(finding.family),
  );

  const ignoredStatic: NormalizedFinding[] = normalizedStatic.filter(
    (finding: NormalizedFinding): boolean => !isScopedFamily(finding.family),
  );

  const ignoredDynamic: NormalizedFinding[] = normalizedDynamic.filter(
    (finding: NormalizedFinding): boolean => !isScopedFamily(finding.family),
  );

  const candidatePairs: CandidatePair[] = [];

  for (let staticIndex = 0; staticIndex < scopedStatic.length; staticIndex += 1) {
    const left = scopedStatic[staticIndex];
    if (!left) {
      continue;
    }

    for (let dynamicIndex = 0; dynamicIndex < scopedDynamic.length; dynamicIndex += 1) {
      const right = scopedDynamic[dynamicIndex];
      if (!right) {
        continue;
      }

      const pairScore = scorePair(left, right, locationDistanceThreshold);

      if (pairScore.score >= thresholdForFamily(left.family)) {
        candidatePairs.push({
          staticIndex,
          dynamicIndex,
          score: pairScore.score,
          ...(pairScore.locationDistance !== undefined
            ? { locationDistance: pairScore.locationDistance }
            : {}),
        });
      }
    }
  }

  candidatePairs.sort((left, right) => {
    if (right.score !== left.score) {
      return right.score - left.score;
    }

    if (
      left.locationDistance !== undefined &&
      right.locationDistance !== undefined &&
      left.locationDistance !== right.locationDistance
    ) {
      return left.locationDistance - right.locationDistance;
    }

    if (left.locationDistance !== undefined && right.locationDistance === undefined) {
      return -1;
    }

    if (left.locationDistance === undefined && right.locationDistance !== undefined) {
      return 1;
    }

    return 0;
  });

  const usedStatic = new Set<number>();
  const usedDynamic = new Set<number>();
  const corroborated: CorroboratedFinding[] = [];

  for (const pair of candidatePairs) {
    if (usedStatic.has(pair.staticIndex) || usedDynamic.has(pair.dynamicIndex)) {
      continue;
    }

    const left = scopedStatic[pair.staticIndex];
    const right = scopedDynamic[pair.dynamicIndex];

    if (!left || !right) {
      continue;
    }

    usedStatic.add(pair.staticIndex);
    usedDynamic.add(pair.dynamicIndex);

    corroborated.push(
      toCorroboratedFinding(
        left,
        right,
        pair.score,
        locationDistanceThreshold,
        pair.locationDistance,
      ),
    );
  }

  const staticOnly = scopedStatic
    .filter(
      (_finding: NormalizedFinding & { family: CorrelationScopeFamily }, index: number): boolean =>
        !usedStatic.has(index),
    )
    .map(toUnmatchedFinding);

  const dynamicOnly = scopedDynamic
    .filter(
      (_finding: NormalizedFinding & { family: CorrelationScopeFamily }, index: number): boolean =>
        !usedDynamic.has(index),
    )
    .map(toUnmatchedFinding);

  const ignoredStaticFindings = ignoredStatic.map(toUnmatchedFinding);
  const ignoredDynamicFindings = ignoredDynamic.map(toUnmatchedFinding);

  const inputs: CorrelatedReport['metadata']['inputs'] = {};
  if (options.staticReportPath !== undefined) inputs.staticReportPath = options.staticReportPath;
  if (options.dynamicReportPath !== undefined) inputs.dynamicReportPath = options.dynamicReportPath;

  const summary = buildCorrelationSummary(
    corroborated,
    staticOnly,
    dynamicOnly,
    ignoredStaticFindings,
    ignoredDynamicFindings,
  );

  return {
    schemaVersion: REPORT_SCHEMA_VERSION,
    reportType: 'correlation',
    metadata: {
      generatedAt: new Date().toISOString(),
      toolName: REPORT_TOOL_NAME,
      ...(buildCorrelationTarget(staticReport, dynamicReport) !== undefined
        ? { target: buildCorrelationTarget(staticReport, dynamicReport) }
        : {}),
      ...(Object.keys(inputs).length > 0 ? { inputs } : {}),
      heuristics: {
        locationDistanceThreshold,
      },
      staticReport: summarizeInputReport(
        staticReport,
        scopedStatic.length,
        ignoredStatic.length,
      ),
      dynamicReport: summarizeInputReport(
        dynamicReport,
        scopedDynamic.length,
        ignoredDynamic.length,
      ),
    },
    summary,
    corroborated,
    staticOnly,
    dynamicOnly,
    ignoredStatic: ignoredStaticFindings,
    ignoredDynamic: ignoredDynamicFindings,
  };
}
