import { handleCorrelationCommand } from './correlation/command.js';
import fs from "node:fs/promises";
import path from "node:path";
import { writeStaticJsonReport } from "./static/scanner/jsonReport.js";
import { collectSourceFiles } from "./static/scanner/fileWalker.js";
import { parseSource } from "./static/scanner/parser.js";
import { printFindings } from "./static/scanner/report.js";
import { runRules } from "./static/engine/ruleEngine.js";
import type { Finding } from "./static/engine/findings.js";
import { domXssRule } from "./static/rules/domXss.js";
import { storageRule } from "./static/rules/storage.js";
import { thirdPartyScriptsRule } from "./static/rules/thirdPartyScripts.js";
import { isJavaScriptLikeFile } from "./static/utils/urls.js";
import {
  DynamicScanTargetUnreachableError,
  runDynamicScan,
} from './dynamic/scanner/dynamicScanner.js';

async function main() {
  const [, , firstArg, ...remainingArgs] = process.argv;

  if (firstArg === "dynamic") {
    process.exitCode = await handleDynamicCommand(remainingArgs);
    return;
  }

  if (firstArg === "correlate") {
    process.exitCode = await handleCorrelationCommand(remainingArgs);
    return;
  }

  const targetPath =
    firstArg !== undefined && !firstArg.startsWith("--") ? firstArg : ".";
  const outputPath = getArgValue(process.argv.slice(2), "--output");
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

  if (outputPath) {
    await writeStaticJsonReport(allFindings, resolvedTarget, outputPath);
    console.log(
      JSON.stringify(
        {
          output: outputPath,
          findingCount: allFindings.length,
        },
        null,
        2,
      ),
    );
    return;
  }

  printFindings(allFindings);
}

async function handleDynamicCommand(args: readonly string[]): Promise<number> {
  const commandArgs = args[0] === 'scan' ? args.slice(1) : args;
  const url = getArgValue(commandArgs, '--url');
  const outputPath = getArgValue(commandArgs, '--output');
  const includeRawEvents = commandArgs.includes('--include-raw');
  const headless = !commandArgs.includes('--headed');

  if (!url) {
    console.error(
      'Usage: node dist/cli.js dynamic scan --url http://localhost:3000 [--output artifacts/dynamic-report.json] [--include-raw] [--headed]',
    );
    return 1;
  }

  try {
    const result = await runDynamicScan({
      url,
      headless,
      outputPath,
      includeRawEvents,
    });

    console.log(JSON.stringify(result, null, 2));
    return 0;
  } catch (error) {
    if (error instanceof DynamicScanTargetUnreachableError) {
      console.error(error.message);
      const detail = error.originalMessage.split(/\r?\n/, 1)[0] ?? '';
      if (detail.length > 0) {
        console.error(`Details: ${detail}`);
      }
      return 1;
    }

    throw error;
  }
}

function getArgValue(args: readonly string[], flag: string): string | undefined {
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
