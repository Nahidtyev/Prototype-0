import { promises as fs } from 'node:fs';
import path from 'node:path';

import { correlateReports } from './correlator.js';
import type { FindingReport, ReportFinding } from './types.js';

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

  return {
    ...value,
    metadata,
    findings,
  } as FindingReport;
}

async function readJsonFile(filePath: string): Promise<unknown> {
  const content = await fs.readFile(filePath, 'utf8');
  return JSON.parse(content) as unknown;
}

export async function handleCorrelationCommand(args: readonly string[]): Promise<number> {
  const staticPath = readOption(args, '--static');
  const dynamicPath = readOption(args, '--dynamic');
  const outputPath = readOption(args, '--output') ?? 'reports/correlated-report.json';

  if (!staticPath || !dynamicPath) {
    console.error(
      'Usage: correlate --static <static-report.json> --dynamic <dynamic-report.json> --output <correlated-report.json>',
    );
    return 1;
  }

  const staticRaw = await readJsonFile(staticPath);
  const dynamicRaw = await readJsonFile(dynamicPath);

  const staticReport = parseReport(staticRaw, 'Static report');
  const dynamicReport = parseReport(dynamicRaw, 'Dynamic report');

  const correlated = correlateReports(staticReport, dynamicReport, {
    staticReportPath: staticPath,
    dynamicReportPath: dynamicPath,
  });

  await fs.mkdir(path.dirname(outputPath), { recursive: true });
  await fs.writeFile(outputPath, `${JSON.stringify(correlated, null, 2)}\n`, 'utf8');

  console.log(
    JSON.stringify(
      {
        output: outputPath,
        summary: correlated.metadata.summary,
      },
      null,
      2,
    ),
  );

  return 0;
}