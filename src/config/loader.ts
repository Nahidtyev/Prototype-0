import fs from 'node:fs/promises';
import path from 'node:path';

import type {
  ConfigBrowserName,
  LoadedPrototype0Config,
  Prototype0Config,
} from './types.js';

const DEFAULT_CONFIG_FILENAME = 'prototype0.config.json';
const SUPPORTED_BROWSERS: readonly ConfigBrowserName[] = [
  'chromium',
  'firefox',
  'webkit',
];

type LoadPrototype0ConfigOptions = {
  cwd?: string;
  explicitPath?: string | undefined;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value);
}

function assertObject(
  value: unknown,
  label: string,
): asserts value is Record<string, unknown> {
  if (!isRecord(value)) {
    throw new Error(`${label} must be an object.`);
  }
}

function assertString(value: unknown, label: string): void {
  if (!isNonEmptyString(value)) {
    throw new Error(`${label} must be a non-empty string.`);
  }
}

function assertBoolean(value: unknown, label: string): void {
  if (typeof value !== 'boolean') {
    throw new Error(`${label} must be a boolean.`);
  }
}

function assertStringArray(value: unknown, label: string): void {
  if (!Array.isArray(value) || value.some((item) => !isNonEmptyString(item))) {
    throw new Error(`${label} must be an array of non-empty strings.`);
  }
}

function assertNumber(value: unknown, label: string): void {
  if (!isFiniteNumber(value) || value < 0) {
    throw new Error(`${label} must be a non-negative number.`);
  }
}

function assertBrowser(value: unknown, label: string): void {
  if (
    !isNonEmptyString(value) ||
    !SUPPORTED_BROWSERS.includes(value as ConfigBrowserName)
  ) {
    throw new Error(
      `${label} must be one of: ${SUPPORTED_BROWSERS.join(', ')}.`,
    );
  }
}

function validateConfig(config: unknown, configPath: string): Prototype0Config {
  if (!isRecord(config)) {
    throw new Error('Config file must contain a JSON object.');
  }

  if (config.projectName !== undefined) {
    assertString(config.projectName, 'Config field "projectName"');
  }

  if (config.targets !== undefined) {
    assertObject(config.targets, 'Config field "targets"');

    if (config.targets.staticPaths !== undefined) {
      assertStringArray(
        config.targets.staticPaths,
        'Config field "targets.staticPaths"',
      );
    }

    if (config.targets.dynamicUrl !== undefined) {
      assertString(config.targets.dynamicUrl, 'Config field "targets.dynamicUrl"');
    }
  }

  if (config.output !== undefined) {
    assertObject(config.output, 'Config field "output"');

    if (config.output.directory !== undefined) {
      assertString(config.output.directory, 'Config field "output.directory"');
    }

    if (config.output.staticReport !== undefined) {
      assertString(
        config.output.staticReport,
        'Config field "output.staticReport"',
      );
    }

    if (config.output.dynamicReport !== undefined) {
      assertString(
        config.output.dynamicReport,
        'Config field "output.dynamicReport"',
      );
    }

    if (config.output.correlatedReport !== undefined) {
      assertString(
        config.output.correlatedReport,
        'Config field "output.correlatedReport"',
      );
    }
  }

  if (config.staticAnalysis !== undefined) {
    assertObject(config.staticAnalysis, 'Config field "staticAnalysis"');

    if (config.staticAnalysis.enabled !== undefined) {
      assertBoolean(
        config.staticAnalysis.enabled,
        'Config field "staticAnalysis.enabled"',
      );
    }

    if (config.staticAnalysis.extensions !== undefined) {
      assertStringArray(
        config.staticAnalysis.extensions,
        'Config field "staticAnalysis.extensions"',
      );
    }

    if (config.staticAnalysis.rules !== undefined) {
      assertObject(
        config.staticAnalysis.rules,
        'Config field "staticAnalysis.rules"',
      );

      if (config.staticAnalysis.rules.domXss !== undefined) {
        assertBoolean(
          config.staticAnalysis.rules.domXss,
          'Config field "staticAnalysis.rules.domXss"',
        );
      }

      if (config.staticAnalysis.rules.storage !== undefined) {
        assertBoolean(
          config.staticAnalysis.rules.storage,
          'Config field "staticAnalysis.rules.storage"',
        );
      }

      if (config.staticAnalysis.rules.thirdPartyScripts !== undefined) {
        assertBoolean(
          config.staticAnalysis.rules.thirdPartyScripts,
          'Config field "staticAnalysis.rules.thirdPartyScripts"',
        );
      }
    }
  }

  if (config.dynamicAnalysis !== undefined) {
    assertObject(config.dynamicAnalysis, 'Config field "dynamicAnalysis"');

    if (config.dynamicAnalysis.enabled !== undefined) {
      assertBoolean(
        config.dynamicAnalysis.enabled,
        'Config field "dynamicAnalysis.enabled"',
      );
    }

    if (config.dynamicAnalysis.browser !== undefined) {
      assertBrowser(
        config.dynamicAnalysis.browser,
        'Config field "dynamicAnalysis.browser"',
      );
    }

    if (config.dynamicAnalysis.headless !== undefined) {
      assertBoolean(
        config.dynamicAnalysis.headless,
        'Config field "dynamicAnalysis.headless"',
      );
    }

    if (config.dynamicAnalysis.timeoutMs !== undefined) {
      assertNumber(
        config.dynamicAnalysis.timeoutMs,
        'Config field "dynamicAnalysis.timeoutMs"',
      );
    }

    if (config.dynamicAnalysis.waitAfterLoadMs !== undefined) {
      assertNumber(
        config.dynamicAnalysis.waitAfterLoadMs,
        'Config field "dynamicAnalysis.waitAfterLoadMs"',
      );
    }

    if (config.dynamicAnalysis.includeRawEvents !== undefined) {
      assertBoolean(
        config.dynamicAnalysis.includeRawEvents,
        'Config field "dynamicAnalysis.includeRawEvents"',
      );
    }
  }

  if (config.correlation !== undefined) {
    assertObject(config.correlation, 'Config field "correlation"');

    if (config.correlation.enabled !== undefined) {
      assertBoolean(
        config.correlation.enabled,
        'Config field "correlation.enabled"',
      );
    }

    if (config.correlation.locationDistanceThreshold !== undefined) {
      assertNumber(
        config.correlation.locationDistanceThreshold,
        'Config field "correlation.locationDistanceThreshold"',
      );
    }
  }

  if (config.reporting !== undefined) {
    assertObject(config.reporting, 'Config field "reporting"');

    if (config.reporting.schemaVersion !== undefined) {
      assertString(
        config.reporting.schemaVersion,
        'Config field "reporting.schemaVersion"',
      );
    }
  }

  return config as Prototype0Config;
}

async function readConfigFile(configPath: string): Promise<Prototype0Config> {
  let content: string;

  try {
    content = await fs.readFile(configPath, 'utf8');
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Could not read config file at ${configPath}: ${message}`);
  }

  let parsed: unknown;

  try {
    parsed = JSON.parse(content) as unknown;
  } catch {
    throw new Error(`Config file is not valid JSON: ${configPath}`);
  }

  try {
    return validateConfig(parsed, configPath);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Invalid config file at ${configPath}: ${message}`);
  }
}

export async function loadPrototype0Config(
  options: LoadPrototype0ConfigOptions = {},
): Promise<LoadedPrototype0Config | undefined> {
  const cwd = options.cwd ?? process.cwd();
  const explicitPath = options.explicitPath;
  const configPath = explicitPath
    ? path.resolve(cwd, explicitPath)
    : path.resolve(cwd, DEFAULT_CONFIG_FILENAME);

  try {
    await fs.access(configPath);
  } catch {
    if (explicitPath) {
      throw new Error(`Config file not found: ${configPath}`);
    }

    return undefined;
  }

  const config = await readConfigFile(configPath);

  return {
    path: configPath,
    baseDir: path.dirname(configPath),
    config,
  };
}

export function resolveConfigRelativePath(
  loadedConfig: LoadedPrototype0Config,
  filePath: string,
): string {
  return path.resolve(loadedConfig.baseDir, filePath);
}

export function resolveConfiguredOutputPath(
  loadedConfig: LoadedPrototype0Config | undefined,
  reportKey: 'staticReport' | 'dynamicReport' | 'correlatedReport',
): string | undefined {
  if (!loadedConfig) {
    return undefined;
  }

  const output = loadedConfig.config.output;
  const fileName = output?.[reportKey];

  if (!isNonEmptyString(fileName)) {
    return undefined;
  }

  if (isNonEmptyString(output?.directory)) {
    return path.resolve(loadedConfig.baseDir, output.directory, fileName);
  }

  return path.resolve(loadedConfig.baseDir, fileName);
}

export function resolveConfiguredStaticTargets(
  loadedConfig: LoadedPrototype0Config | undefined,
): string[] {
  const staticPaths = loadedConfig?.config.targets?.staticPaths;

  if (!staticPaths || staticPaths.length === 0) {
    return [];
  }

  return staticPaths.map((entry) => resolveConfigRelativePath(loadedConfig, entry));
}

export function getDefaultDynamicUrl(
  loadedConfig: LoadedPrototype0Config | undefined,
): string | undefined {
  const value = loadedConfig?.config.targets?.dynamicUrl;

  if (!isNonEmptyString(value) || !loadedConfig) {
    return undefined;
  }

  return value;
}
