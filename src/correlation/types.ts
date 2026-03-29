import type { ReportMetadata } from '../reporting/schema.js';
import { REPORT_SCHEMA_VERSION } from '../reporting/schema.js';

export const DEFAULT_LOCATION_DISTANCE_THRESHOLD = 8 as const;

export type CorrelationScopeFamily = 'dom' | 'storage' | 'script';
export type CorrelationFamily = CorrelationScopeFamily | 'unknown';
export type CorrelationMode = 'static' | 'dynamic';

export interface CorrelatorOptions {
  staticReportPath?: string | undefined;
  dynamicReportPath?: string | undefined;
  locationDistanceThreshold?: number | undefined;
}

export interface ReportFinding {
  category?: string;
  type?: string;
  subtype?: string;
  severity?: string;
  title?: string;
  description?: string;
  source?: string;
  timestamp?: string;
  location?: string | Record<string, unknown>;
  locationHint?: string;
  correlationFingerprint?: string;
  correlationSignals?: Record<string, unknown>;
  evidence?: Record<string, unknown>;
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
  schemaVersion?: string;
  reportType?: string;
  metadata?: Record<string, unknown>;
  summary?: Record<string, unknown>;
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
  matchSummary: {
    matchedFamily: CorrelationScopeFamily;
    matchedSignals: string[];
    score: number;
    matchKind: 'fingerprint' | 'signal';
    locationDistance?: number | undefined;
    locationThresholdUsed?: number | undefined;
    reasoning: string;
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

export interface CorrelationInputSummary {
  reportType?: string | undefined;
  schemaVersion?: string | undefined;
  findingCount: number;
  scopedCount: number;
  ignoredCount: number;
}

export interface CorrelationReportSummary {
  corroboratedCount: number;
  corroboratedByFamily: Partial<Record<CorrelationScopeFamily, number>>;
  staticOnlyCount: number;
  dynamicOnlyCount: number;
  ignoredStaticCount: number;
  ignoredDynamicCount: number;
}

export interface CorrelatedReport {
  schemaVersion: typeof REPORT_SCHEMA_VERSION;
  reportType: 'correlation';
  metadata: ReportMetadata & {
    inputs?: {
      staticReportPath?: string;
      dynamicReportPath?: string;
    };
    heuristics?: {
      locationDistanceThreshold: number;
    };
    staticReport: CorrelationInputSummary;
    dynamicReport: CorrelationInputSummary;
  };
  summary: CorrelationReportSummary;
  corroborated: CorroboratedFinding[];
  staticOnly: UnmatchedFinding[];
  dynamicOnly: UnmatchedFinding[];
  ignoredStatic: UnmatchedFinding[];
  ignoredDynamic: UnmatchedFinding[];
}
