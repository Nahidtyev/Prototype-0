import path from "node:path";

import { runRules } from "./engine/ruleEngine.js";
import type { ParseFailure, ParsedFile, RuleDefinition } from "./engine/findings.js";
import { domXssRule } from "./rules/domXss.js";
import { findSourceFiles } from "./scanner/fileWalker.js";
import { isParsedFile, parseFile } from "./scanner/parser.js";

const rules: RuleDefinition[] = [domXssRule];

function formatFilePath(filePath: string): string {
  return path.relative(process.cwd(), filePath) || path.basename(filePath);
}

function printParseFailures(parseFailures: ParseFailure[]): void {
  for (const failure of parseFailures) {
    const line = failure.location?.line ?? 0;
    const message = `${formatFilePath(failure.filePath)}:${line} parse-error error ${failure.message}`;
    console.error(message);
  }
}

function printFindings(parsedFindings: ReturnType<typeof runRules>): void {
  for (const finding of parsedFindings) {
    const line = finding.location?.line ?? 0;
    console.log(
      `${formatFilePath(finding.filePath)}:${line} ${finding.ruleId} ${finding.severity} ${finding.message}`,
    );
  }
}

async function main(): Promise<void> {
  const targetPath = process.argv[2] ?? ".";
  const filePaths = await findSourceFiles(targetPath);

  const parsedResults = await Promise.all(filePaths.map((filePath) => parseFile(filePath)));
  const parsedFiles: ParsedFile[] = [];
  const parseFailures: ParseFailure[] = [];

  for (const result of parsedResults) {
    if (isParsedFile(result)) {
      parsedFiles.push(result);
      continue;
    }

    parseFailures.push(result);
  }

  const findings = runRules(parsedFiles, rules);

  printParseFailures(parseFailures);
  printFindings(findings);

  if (parseFailures.length === 0 && findings.length === 0) {
    console.log("No findings.");
  }

  process.exitCode = findings.length > 0 || parseFailures.length > 0 ? 1 : 0;
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(message);
  process.exitCode = 1;
});
