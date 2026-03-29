import { promises as fs } from 'node:fs';
import path from 'node:path';

import { correlateReports } from './correlator.js';
import {
  DEFAULT_LOCATION_DISTANCE_THRESHOLD,
  type FindingReport,
  type ReportFinding,
} from './types.js';

export interface CorrelationCommandDefaults {
  defaultStaticPath?: string | undefined;
  defaultDynamicPath?: string | undefined;
  defaultOutputPath?: string | undefined;
  locationDistanceThreshold?: number | undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function readOption(args: readonly string[], name: string): string | undefined {
  const index = args.indexOf(name);

  if (index === -1) {
    return undefined;
  }

  const value = args[index + 1];
  if (!value || value.startsWith('--')) {
    throw new Error(`Missing value for ${name}.`);
  }

  return value;
}

function parseReport(value: unknown, label: string): FindingReport {
  if (!isRecord(value)) {
    throw new Error(`${label} must be a JSON object.`);
  }

  const findingsRaw = value.findings;
  if (!Array.isArray(findingsRaw)) {
    throw new Error(`${label} must contain a "findings" array.`);
  }

  const findings: ReportFinding[] = findingsRaw.map((item, index) => {
    if (!isRecord(item)) {
      throw new Error(`${label}.findings[${index}] must be an object.`);
    }

    return item as ReportFinding;
  });

  const metadata = isRecord(value.metadata) ? value.metadata : undefined;
  const summary = isRecord(value.summary) ? value.summary : undefined;
  const schemaVersion =
    typeof value.schemaVersion === 'string' ? value.schemaVersion : undefined;
  const reportType =
    typeof value.reportType === 'string' ? value.reportType : undefined;

  return {
    ...value,
    ...(schemaVersion !== undefined ? { schemaVersion } : {}),
    ...(reportType !== undefined ? { reportType } : {}),
    metadata,
    ...(summary !== undefined ? { summary } : {}),
    findings,
  } as FindingReport;
}

async function readJsonFile(filePath: string): Promise<unknown> {
  let content: string;

  try {
    content = await fs.readFile(filePath, 'utf8');
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Could not read JSON file ${filePath}: ${message}`);
  }

  try {
    return JSON.parse(content) as unknown;
  } catch {
    throw new Error(`File is not valid JSON: ${filePath}`);
  }
}

async function assertReadableFile(filePath: string, label: string): Promise<void> {
  try {
    const stats = await fs.stat(filePath);

    if (!stats.isFile()) {
      throw new Error(`${label} must point to a file: ${filePath}`);
    }
  } catch (error) {
    if (error instanceof Error && 'code' in error && error.code === 'ENOENT') {
      throw new Error(`${label} not found: ${filePath}`);
    }

    if (error instanceof Error) {
      throw error;
    }

    throw new Error(`${label} could not be accessed: ${filePath}`);
  }
}

function printCorrelationUsage(): void {
  console.error(
    'Usage: correlate --static <static-report.json> --dynamic <dynamic-report.json> [--output <correlated-report.json>] [--config <path>]',
  );
}

export async function handleCorrelationCommand(
  args: readonly string[],
  defaults: CorrelationCommandDefaults = {},
): Promise<number> {
  if (args.includes('--help') || args.includes('-h')) {
    printCorrelationUsage();
    return 0;
  }

  const staticPath = readOption(args, '--static') ?? defaults.defaultStaticPath;
  const dynamicPath = readOption(args, '--dynamic') ?? defaults.defaultDynamicPath;
  const outputPath =
    readOption(args, '--output') ??
    defaults.defaultOutputPath ??
    'reports/correlated-report.json';
  const locationDistanceThreshold =
    defaults.locationDistanceThreshold ?? DEFAULT_LOCATION_DISTANCE_THRESHOLD;

  if (!staticPath || !dynamicPath) {
    console.error(
      'Correlation requires both static and dynamic report inputs. Pass --static/--dynamic or provide them through config defaults.',
    );
    printCorrelationUsage();
    return 1;
  }

  await assertReadableFile(staticPath, 'Static report');
  await assertReadableFile(dynamicPath, 'Dynamic report');

  const staticRaw = await readJsonFile(staticPath);
  const dynamicRaw = await readJsonFile(dynamicPath);

  const staticReport = parseReport(staticRaw, 'Static report');
  const dynamicReport = parseReport(dynamicRaw, 'Dynamic report');

  const correlated = correlateReports(staticReport, dynamicReport, {
    staticReportPath: staticPath,
    dynamicReportPath: dynamicPath,
    locationDistanceThreshold,
  });

  try {
    await fs.mkdir(path.dirname(outputPath), { recursive: true });
    await fs.writeFile(outputPath, `${JSON.stringify(correlated, null, 2)}\n`, 'utf8');
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(
      `Could not write correlated report to ${outputPath}: ${message}`,
    );
  }

  console.log(
    JSON.stringify(
      {
        output: outputPath,
        summary: correlated.summary,
      },
      null,
      2,
    ),
  );

  return 0;
}
