import chalk from "chalk";
import type { Finding } from "../engine/findings.js";

function colorSeverity(severity: Finding["severity"]): string {
  if (severity === "HIGH") return chalk.red(severity);
  if (severity === "MEDIUM") return chalk.yellow(severity);
  return chalk.blue(severity);
}

export function printFindings(findings: Finding[]): void {
  if (findings.length === 0) {
    console.log(chalk.green("No findings detected."));
    return;
  }

  for (const finding of findings) {
    const location =
      finding.line !== undefined
        ? `${finding.filePath}:${finding.line}:${(finding.column ?? 0) + 1}`
        : finding.filePath;

    console.log(
      `[${colorSeverity(finding.severity)}] ${chalk.cyan(finding.ruleId)} ${location}`,
    );
    console.log(`  ${finding.message}`);
  }
}