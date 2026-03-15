import fs from "node:fs/promises";
import path from "node:path";
import { collectSourceFiles } from "./scanner/fileWalker.js";
import { parseSource } from "./scanner/parser.js";
import { printFindings } from "./scanner/report.js";
import { runRules } from "./engine/ruleEngine.js";
import type { Finding } from "./engine/findings.js";
import { domXssRule } from "./rules/domXss.js";
import { storageRule } from "./rules/storage.js";
import { thirdPartyScriptsRule } from "./rules/thirdPartyScripts.js";
import { isJavaScriptLikeFile } from "./utils/urls.js";
import { runDynamicScan } from './dynamic/scanner/dynamicScanner.js';
async function main() {
  const targetPath = process.argv[2] ?? ".";
  const resolvedTarget = path.resolve(targetPath);

  const files = await collectSourceFiles(resolvedTarget);

  if (files.length === 0) {
    console.log("No source files found.");
    return;
  }

  const allFindings: Finding[] = [];

  for (const filePath of files) {
    try {
      const code = await fs.readFile(filePath, "utf8");
      const ast = isJavaScriptLikeFile(filePath) ? parseSource(code, filePath) : null;

      const findings = runRules(
        { filePath, code, ast },
        [domXssRule, storageRule, thirdPartyScriptsRule],
      );

      allFindings.push(...findings);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown parsing error";

      allFindings.push({
        ruleId: "PARSER_ERROR",
        severity: "LOW",
        message,
        filePath,
      });
    }
  }

  printFindings(allFindings);
}
const args = process.argv.slice(2);
const command = args[0];

if (command === 'dynamic') {
  const url = getArgValue(args, '--url');
  const outputPath = getArgValue(args, '--output');
  const includeRawEvents = args.includes('--include-raw');
  const headless = !args.includes('--headed');

  if (!url) {
    console.error(
      'Usage: node dist/cli.js dynamic --url http://localhost:3000 [--output artifacts/dynamic-report.json] [--include-raw] [--headed]',
    );
    process.exit(1);
  }

  const result = await runDynamicScan({
    url,
    headless,
    outputPath,
    includeRawEvents,
  });

  console.log(JSON.stringify(result, null, 2));
  process.exit(0);
}
function getArgValue(args: string[], flag: string): string | undefined {
  const index = args.indexOf(flag);
  if (index === -1) {
    return undefined;
  }

  return args[index + 1];
}
main().catch((error) => {
  console.error(error);
  process.exit(1);
});