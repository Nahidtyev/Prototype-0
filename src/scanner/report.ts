import path from "node:path";

import chalk from "chalk";

import type { Finding, ParseFailure } from "../engine/findings.js";

const SEVERITY_COLOR = {
  low: chalk.blue,
  medium: chalk.yellow,
  high: chalk.red,
} as const;

export function printReport(findings: Finding[], parseFailures: ParseFailure[], rootPath: string): void {
  if (parseFailures.length > 0) {
    console.log(chalk.yellow(`Parse failures: ${parseFailures.length}`));

    for (const failure of parseFailures) {
      const location = failure.location ? `:${failure.location.line}:${failure.location.column}` : "";
      console.log(`  ${path.relative(rootPath, failure.filePath)}${location} ${failure.message}`);
    }

    console.log("");
  }

  if (findings.length === 0) {
    console.log(chalk.green("No findings detected."));
    return;
  }

  console.log(chalk.bold(`Findings: ${findings.length}`));

  for (const finding of findings) {
    const severity = SEVERITY_COLOR[finding.severity](finding.severity.toUpperCase().padEnd(6));
    const location = finding.location ? `:${finding.location.line}:${finding.location.column}` : "";
    const filePath = path.relative(rootPath, finding.filePath);

    console.log(`${severity} ${filePath}${location} ${finding.ruleId}`);
    console.log(`  ${finding.message}`);

    if (finding.snippet) {
      console.log(chalk.gray(`  ${finding.snippet}`));
    }
  }
}
