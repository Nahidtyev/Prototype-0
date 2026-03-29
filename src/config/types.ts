export type ConfigBrowserName = 'chromium' | 'firefox' | 'webkit';

export interface Prototype0TargetsConfig {
  staticPaths?: string[] | undefined;
  dynamicUrl?: string | undefined;
}

export interface Prototype0OutputConfig {
  directory?: string | undefined;
  staticReport?: string | undefined;
  dynamicReport?: string | undefined;
  correlatedReport?: string | undefined;
}

export interface Prototype0StaticRulesConfig {
  domXss?: boolean | undefined;
  storage?: boolean | undefined;
  thirdPartyScripts?: boolean | undefined;
}

export interface Prototype0StaticAnalysisConfig {
  enabled?: boolean | undefined;
  extensions?: string[] | undefined;
  rules?: Prototype0StaticRulesConfig | undefined;
}

export interface Prototype0DynamicAnalysisConfig {
  enabled?: boolean | undefined;
  browser?: ConfigBrowserName | undefined;
  headless?: boolean | undefined;
  timeoutMs?: number | undefined;
  waitAfterLoadMs?: number | undefined;
  includeRawEvents?: boolean | undefined;
}

export interface Prototype0CorrelationConfig {
  enabled?: boolean | undefined;
  locationDistanceThreshold?: number | undefined;
}

export interface Prototype0ReportingConfig {
  schemaVersion?: string | undefined;
}

export interface Prototype0Config {
  projectName?: string | undefined;
  targets?: Prototype0TargetsConfig | undefined;
  output?: Prototype0OutputConfig | undefined;
  staticAnalysis?: Prototype0StaticAnalysisConfig | undefined;
  dynamicAnalysis?: Prototype0DynamicAnalysisConfig | undefined;
  correlation?: Prototype0CorrelationConfig | undefined;
  reporting?: Prototype0ReportingConfig | undefined;
}

export interface LoadedPrototype0Config {
  path: string;
  baseDir: string;
  config: Prototype0Config;
}
