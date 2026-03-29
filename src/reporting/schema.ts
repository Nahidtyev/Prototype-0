export const REPORT_SCHEMA_VERSION = '0.2.0' as const;
export const REPORT_TOOL_NAME = 'Prototype-0' as const;

export type ReportType = 'static' | 'dynamic' | 'correlation';
export type ReportSeverity = 'LOW' | 'MEDIUM' | 'HIGH';

export interface SeverityCounts {
  LOW: number;
  MEDIUM: number;
  HIGH: number;
}

export interface FindingLocation {
  hint?: string | undefined;
  path?: string | undefined;
  line?: number | undefined;
  column?: number | undefined;
  inlineScriptBlockIndex?: number | undefined;
  functionName?: string | undefined;
  pageUrl?: string | undefined;
  frameUrl?: string | undefined;
}

export interface NormalizedFindingCore {
  category: string;
  type: string;
  subtype?: string | undefined;
  severity?: string | undefined;
  title: string;
  description: string;
  source?: string | undefined;
  timestamp?: string | undefined;
  location?: FindingLocation | undefined;
  locationHint?: string | undefined;
  evidence?: Record<string, unknown> | undefined;
  correlationFingerprint?: string | undefined;
}

export interface ReportMetadata {
  generatedAt: string;
  toolName: typeof REPORT_TOOL_NAME;
  target?: string | undefined;
}

export interface FindingSummary {
  totalFindings: number;
  findingsBySeverity: SeverityCounts;
  findingsByType: Record<string, number>;
}
