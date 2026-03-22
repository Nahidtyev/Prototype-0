import type {
  CorrelatedReport,
  CorrelationFamily,
  CorrelationMode,
  CorrelationScopeFamily,
  CorroboratedFinding,
  FindingReport,
  NormalizedFinding,
  ReportFinding,
  UnmatchedFinding,
} from './types.js';

interface CorrelateOptions {
  staticReportPath?: string;
  dynamicReportPath?: string;
}

interface CandidatePair {
  staticIndex: number;
  dynamicIndex: number;
  score: number;
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
    normalizeLocationToken(asString(finding['file'])) ??
    normalizeLocationToken(asString(finding['filePath'])) ??
    normalizeLocationToken(asString(finding['path']))
  );
}

function parseLocation(
  locationToken: string | undefined,
): { path?: string; line?: number; column?: number } {
  if (!locationToken) {
    return {};
  }

  const match = locationToken.match(/^(.*?)(?::(\d+))(?::(\d+))?$/);
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

function basename(input: string | undefined): string | undefined {
  if (!input) {
    return undefined;
  }

  const normalized = input.replace(/\\/g, '/');
  const parts = normalized.split('/');
  return parts.length > 0 ? parts[parts.length - 1] : normalized;
}

function locationsAreNear(
  staticLocation: string | undefined,
  dynamicLocation: string | undefined,
): boolean {
  if (!staticLocation || !dynamicLocation) {
    return false;
  }

  if (staticLocation === dynamicLocation) {
    return true;
  }

  const left = parseLocation(staticLocation);
  const right = parseLocation(dynamicLocation);

  const leftBase = basename(left.path);
  const rightBase = basename(right.path);

  const samePath =
    (left.path !== undefined && right.path !== undefined && left.path === right.path) ||
    (left.path !== undefined &&
      right.path !== undefined &&
      left.path.endsWith(right.path)) ||
    (left.path !== undefined &&
      right.path !== undefined &&
      right.path.endsWith(left.path)) ||
    (leftBase !== undefined && rightBase !== undefined && leftBase === rightBase);

  if (samePath && left.line !== undefined && right.line !== undefined) {
    return Math.abs(left.line - right.line) <= 5;
  }

  if (samePath && left.line === undefined && right.line === undefined) {
    return true;
  }

  if (left.line !== undefined && right.line !== undefined) {
    return Math.abs(left.line - right.line) <= 2;
  }

  return false;
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

function scorePair(staticFinding: NormalizedFinding, dynamicFinding: NormalizedFinding): number {
  if (!isScopedFamily(staticFinding.family) || !isScopedFamily(dynamicFinding.family)) {
    return 0;
  }

  if (staticFinding.family !== dynamicFinding.family) {
    return 0;
  }

  if (
    staticFinding.correlationFingerprint &&
    dynamicFinding.correlationFingerprint &&
    staticFinding.correlationFingerprint === dynamicFinding.correlationFingerprint
  ) {
    return 100;
  }

  switch (staticFinding.family) {
    case 'script': {
      if (
        staticFinding.resourceToken &&
        dynamicFinding.resourceToken &&
        staticFinding.resourceToken === dynamicFinding.resourceToken
      ) {
        return 100;
      }

      return 0;
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

      if (locationsAreNear(staticFinding.locationToken, dynamicFinding.locationToken)) {
        score += 10;
      }

      return score;
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

      if (locationsAreNear(staticFinding.locationToken, dynamicFinding.locationToken)) {
        score += 10;
      }

      return score;
    }

    default:
      return 0;
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

function toCorroboratedFinding(
  staticFinding: NormalizedFinding & { family: CorrelationScopeFamily },
  dynamicFinding: NormalizedFinding & { family: CorrelationScopeFamily },
  score: number,
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

  return {
    family: staticFinding.family,
    score,
    matchKind,
    matchSignals,
    staticFinding: staticFinding.finding,
    dynamicFinding: dynamicFinding.finding,
  };
}

export function correlateReports(
  staticReport: FindingReport,
  dynamicReport: FindingReport,
  options: CorrelateOptions = {},
): CorrelatedReport {
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

    const score = scorePair(left, right);

    if (score >= thresholdForFamily(left.family)) {
      candidatePairs.push({ staticIndex, dynamicIndex, score });
    }
  }
}

  candidatePairs.sort((a, b) => b.score - a.score);

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

  corroborated.push(toCorroboratedFinding(left, right, pair.score));
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

  const inputs: CorrelatedReport['metadata']['inputs'] = {};
  if (options.staticReportPath !== undefined) inputs.staticReportPath = options.staticReportPath;
  if (options.dynamicReportPath !== undefined) inputs.dynamicReportPath = options.dynamicReportPath;

  return {
    metadata: {
      correlationVersion: 1,
      generatedAt: new Date().toISOString(),
      ...(Object.keys(inputs).length > 0 ? { inputs } : {}),
      staticReportSummary: {
        findingCount: staticReport.findings.length,
        scopedCount: scopedStatic.length,
        ignoredCount: ignoredStatic.length,
      },
      dynamicReportSummary: {
        findingCount: dynamicReport.findings.length,
        scopedCount: scopedDynamic.length,
        ignoredCount: ignoredDynamic.length,
      },
      summary: {
        corroboratedCount: corroborated.length,
        staticOnlyCount: staticOnly.length,
        dynamicOnlyCount: dynamicOnly.length,
        ignoredStaticCount: ignoredStatic.length,
        ignoredDynamicCount: ignoredDynamic.length,
      },
    },
    corroborated,
    staticOnly,
    dynamicOnly,
    ignoredStatic: ignoredStatic.map(toUnmatchedFinding),
    ignoredDynamic: ignoredDynamic.map(toUnmatchedFinding),
  };
}
