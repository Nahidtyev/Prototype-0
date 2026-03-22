export type CorrelationScopeFamily = 'dom' | 'storage' | 'script';
export type CorrelationFamily = CorrelationScopeFamily | 'unknown';
export type CorrelationMode = 'static' | 'dynamic';

export interface ReportFinding {
  category?: string;
  type?: string;
  subtype?: string;
  severity?: string;
  title?: string;
  description?: string;
  source?: string;
  timestamp?: string;
  location?: string;
  locationHint?: string;
  correlationFingerprint?: string;
  sink?: string;
  storageKey?: string;
  storageKind?: string;
  resourceUrl?: string;
  scriptUrl?: string;
  url?: string;
  src?: string;
  [key: string]: unknown;
}

export interface FindingReport {
  metadata?: Record<string, unknown>;
  findings: ReportFinding[];
  [key: string]: unknown;
}

export interface NormalizedFinding {
  index: number;
  mode: CorrelationMode;
  family: CorrelationFamily;
  finding: ReportFinding;
  correlationFingerprint?: string;
  sinkToken?: string;
  storageKeyToken?: string;
  storageKind?: string;
  resourceToken?: string;
  locationToken?: string;
  typeToken?: string;
  titleToken?: string;
}

export interface CorroboratedFinding {
  family: CorrelationScopeFamily;
  score: number;
  matchKind: 'fingerprint' | 'signal';
  matchSignals: {
    correlationFingerprint?: string;
    sinkToken?: string;
    storageKeyToken?: string;
    storageKind?: string;
    resourceToken?: string;
    staticLocation?: string;
    dynamicLocation?: string;
  };
  staticFinding: ReportFinding;
  dynamicFinding: ReportFinding;
}

export interface UnmatchedFinding {
  family: CorrelationFamily;
  normalizedSignals: {
    correlationFingerprint?: string;
    sinkToken?: string;
    storageKeyToken?: string;
    storageKind?: string;
    resourceToken?: string;
    locationToken?: string;
  };
  finding: ReportFinding;
}

export interface CorrelatedReport {
  metadata: {
    correlationVersion: 1;
    generatedAt: string;
    inputs?: {
      staticReportPath?: string;
      dynamicReportPath?: string;
    };
    staticReportSummary: {
      findingCount: number;
      scopedCount: number;
      ignoredCount: number;
    };
    dynamicReportSummary: {
      findingCount: number;
      scopedCount: number;
      ignoredCount: number;
    };
    summary: {
      corroboratedCount: number;
      staticOnlyCount: number;
      dynamicOnlyCount: number;
      ignoredStaticCount: number;
      ignoredDynamicCount: number;
    };
  };
  corroborated: CorroboratedFinding[];
  staticOnly: UnmatchedFinding[];
  dynamicOnly: UnmatchedFinding[];
  ignoredStatic: UnmatchedFinding[];
  ignoredDynamic: UnmatchedFinding[];
}