import type { Finding, ParsedFile, RuleDefinition } from "./findings.js";

export function runRules(files: ParsedFile[], rules: RuleDefinition[]): Finding[] {
  const findings: Finding[] = [];

  for (const file of files) {
    for (const rule of rules) {
      findings.push(...rule.run({ file }));
    }
  }

  return findings.sort((left, right) => {
    if (left.filePath === right.filePath) {
      return (left.location?.line ?? Number.MAX_SAFE_INTEGER) - (right.location?.line ?? Number.MAX_SAFE_INTEGER);
    }

    return left.filePath.localeCompare(right.filePath);
  });
}
