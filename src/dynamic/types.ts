import type {
  FindingLocation,
  FindingSummary,
  NormalizedFindingCore,
} from '../reporting/schema.js';
import { REPORT_SCHEMA_VERSION } from '../reporting/schema.js';

export type DynamicCategory =
  | 'DOM_XSS'
  | 'INSECURE_STORAGE'
  | 'THIRD_PARTY_SCRIPT';

export type DynamicSeverity = 'LOW' | 'MEDIUM' | 'HIGH';
export type DynamicBrowserName = 'chromium' | 'firefox' | 'webkit';

export type DynamicRuleId =
  | 'DOM_SINK_USAGE'
  | 'BROWSER_STORAGE_WRITE'
  | 'DYNAMIC_SCRIPT_CREATION'
  | 'SCRIPT_SRC_ASSIGNMENT'
  | 'EXTERNAL_SCRIPT_LOAD';

export type RuntimeEventType =
  | 'innerHTML'
  | 'outerHTML'
  | 'document.write'
  | 'eval'
  | 'Function'
  | 'localStorage.setItem'
  | 'sessionStorage.setItem'
  | 'script.create'
  | 'script.src'
  | 'script.setAttribute.src'
  | 'script.appendChild'
  | 'script.insertBefore';

export interface RuntimeLocation {
  pageUrl: string;
  frameUrl?: string | undefined;
  stack?: string | undefined;
}

export interface RuntimeEventBase {
  type: RuntimeEventType;
  timestamp: string;
  location: RuntimeLocation;
}

export interface DomSinkRuntimeEvent extends RuntimeEventBase {
  type: 'innerHTML' | 'outerHTML' | 'document.write' | 'eval' | 'Function';
  valuePreview?: string | undefined;
}

export interface StorageRuntimeEvent extends RuntimeEventBase {
  type: 'localStorage.setItem' | 'sessionStorage.setItem';
  key?: string | undefined;
  valuePreview?: string | undefined;
}

export interface ScriptRuntimeEvent extends RuntimeEventBase {
  type:
    | 'script.create'
    | 'script.src'
    | 'script.setAttribute.src'
    | 'script.appendChild'
    | 'script.insertBefore';
  src?: string | undefined;
  isExternal?: boolean | undefined;
  tagName?: string | undefined;
}

export type RawRuntimeEvent =
  | DomSinkRuntimeEvent
  | StorageRuntimeEvent
  | ScriptRuntimeEvent;

export interface RawNetworkEvent {
  type: 'external-script-request';
  timestamp: string;
  pageUrl: string;
  frameUrl?: string | undefined;
  requestUrl: string;
  method: string;
  resourceType: 'script';
  isExternal: boolean;
}

export interface DynamicCorrelation {
  fingerprint: string;
  locationHint?: string | undefined;
}

export interface DynamicFinding {
  id: string;
  source: 'dynamic';
  ruleId: DynamicRuleId;
  category: DynamicCategory;
  severity: DynamicSeverity;
  message: string;
  pageUrl: string;
  frameUrl?: string | undefined;
  observedAt: string;
  evidence: Record<string, unknown>;
  correlation: DynamicCorrelation;
}

export interface DynamicScanMetadata {
  generatedAt: string;
  toolName: 'Prototype-0';
  target: string;
  startedAt: string;
  finishedAt: string;
  targetUrl: string;
  browser: DynamicBrowserName;
  findingCount: number;
}

export interface DynamicScanSummary extends FindingSummary {
  rawRuntimeEventCount: number;
  rawNetworkEventCount: number;
}

export interface DynamicScanResult {
  schemaVersion: typeof REPORT_SCHEMA_VERSION;
  reportType: 'dynamic';
  metadata: DynamicScanMetadata;
  summary: DynamicScanSummary;
  findings: NormalizedFinding[];
  rawEvents?: {
    runtime: RawRuntimeEvent[];
    network: RawNetworkEvent[];
  } | undefined;
}

export interface DynamicScanOptions {
  url: string;
  browserName?: DynamicBrowserName | undefined;
  headless?: boolean | undefined;
  timeoutMs?: number | undefined;
  postLoadWaitMs?: number | undefined;
  outputPath?: string | undefined;
  includeRawEvents?: boolean | undefined;
}


export interface DynamicRuntimeEvent {
  type: string;
  timestamp?: string;
  location?: RuntimeLocation;
  valuePreview?: string;
  url?: string;
  [key: string]: unknown;
}

export interface DynamicNetworkEvent {
  type: string;
  timestamp?: string;
  location?: RuntimeLocation;
  valuePreview?: string;
  url?: string;
  [key: string]: unknown;
}

export type CorrelationSignals = {
  findingFamily?: "dom" | "storage" | "script";
  sink?: string;
  locationToken?: string;
  storageKeyToken?: string;
  resourceToken?: string;
};

export interface NormalizedFinding extends NormalizedFindingCore {
  type:
    | "DOM_SINK_USAGE"
    | "BROWSER_STORAGE_WRITE"
    | "DYNAMIC_SCRIPT_CREATION"
    | "SCRIPT_SRC_ASSIGNMENT"
    | "EXTERNAL_SCRIPT_LOAD";
  category: "dynamic";
  subtype: "dom" | "storage" | "script";
  severity: "LOW" | "MEDIUM" | "HIGH";
  title: string;
  description: string;
  source: "runtime" | "network";
  timestamp?: string;
  location?: FindingLocation | undefined;
  locationHint: string;
  correlationFingerprint: string;
  correlationSignals?: CorrelationSignals;
  evidence: Record<string, unknown>;
}
