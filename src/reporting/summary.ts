import type { FindingSummary, ReportSeverity, SeverityCounts } from './schema.js';

type SummarizableFinding = {
  type?: string | undefined;
  severity?: string | undefined;
};

const KNOWN_SEVERITIES: readonly ReportSeverity[] = ['LOW', 'MEDIUM', 'HIGH'];

export function createEmptySeverityCounts(): SeverityCounts {
  return {
    LOW: 0,
    MEDIUM: 0,
    HIGH: 0,
  };
}

export function incrementCount(
  counts: Record<string, number>,
  key: string | undefined,
): void {
  if (!key) {
    return;
  }

  counts[key] = (counts[key] ?? 0) + 1;
}

export function buildFindingSummary(
  findings: readonly SummarizableFinding[],
): FindingSummary {
  const findingsBySeverity = createEmptySeverityCounts();
  const findingsByType: Record<string, number> = {};

  for (const finding of findings) {
    if (
      finding.severity !== undefined &&
      KNOWN_SEVERITIES.includes(finding.severity as ReportSeverity)
    ) {
      findingsBySeverity[finding.severity as ReportSeverity] += 1;
    }

    incrementCount(findingsByType, finding.type);
  }

  return {
    totalFindings: findings.length,
    findingsBySeverity,
    findingsByType,
  };
}
