import fs from 'node:fs/promises';
import path from 'node:path';

import { handleCorrelationCommand } from './correlation/command.js';
import {
  getDefaultDynamicUrl,
  loadPrototype0Config,
  resolveConfiguredOutputPath,
  resolveConfiguredStaticTargets,
} from './config/loader.js';
import type { LoadedPrototype0Config } from './config/types.js';
import {
  DynamicScanSetupError,
  DynamicScanTargetUnreachableError,
  runDynamicScan,
} from './dynamic/scanner/dynamicScanner.js';
import type { DynamicBrowserName } from './dynamic/types.js';
import type { Finding, Rule } from './static/engine/findings.js';
import { runRules } from './static/engine/ruleEngine.js';
import { domXssRule } from './static/rules/domXss.js';
import { storageRule } from './static/rules/storage.js';
import { thirdPartyScriptsRule } from './static/rules/thirdPartyScripts.js';
import { collectSourceFiles } from './static/scanner/fileWalker.js';
import { extractInlineScriptBlocks } from './static/scanner/htmlInlineScripts.js';
import { writeStaticJsonReport } from './static/scanner/jsonReport.js';
import { parseSource } from './static/scanner/parser.js';
import { printFindings } from './static/scanner/report.js';
import { isHtmlFile, isJavaScriptLikeFile } from './static/utils/urls.js';

const MAIN_USAGE = [
  'Usage:',
  '  npm run dev -- [--config <path>] <target-path> [--output <static-report.json>]',
  '  npm run dev -- [--config <path>] dynamic scan --url <target-url> [--output <dynamic-report.json>] [--include-raw] [--headed]',
  '  npm run dev -- [--config <path>] correlate --static <static-report.json> --dynamic <dynamic-report.json> [--output <correlated-report.json>]',
].join('\n');

const STATIC_USAGE = [
  'Usage:',
  '  npm run dev -- [--config <path>] <target-path> [--output <static-report.json>]',
  '  npm run dev -- [--config <path>] --output <static-report.json>',
].join('\n');

const DYNAMIC_USAGE = [
  'Usage:',
  '  npm run dev -- [--config <path>] dynamic scan --url <target-url> [--output <dynamic-report.json>] [--include-raw] [--headed]',
].join('\n');

function hasHelpFlag(args: readonly string[]): boolean {
  return args.includes('--help') || args.includes('-h');
}

function printMainUsage(): void {
  console.log(MAIN_USAGE);
}

function printStaticUsage(): void {
  console.log(STATIC_USAGE);
}

function printDynamicUsage(): void {
  console.log(DYNAMIC_USAGE);
}

function consumeOption(
  args: readonly string[],
  flag: string,
): { args: string[]; value?: string | undefined } {
  const nextArgs: string[] = [];
  let value: string | undefined;

  for (let index = 0; index < args.length; index += 1) {
    const current = args[index];

    if (current === undefined) {
      continue;
    }

    if (current !== flag) {
      nextArgs.push(current);
      continue;
    }

    const optionValue = args[index + 1];

    if (!optionValue || optionValue.startsWith('--')) {
      throw new Error(`Missing value for ${flag}.`);
    }

    value = optionValue;
    index += 1;
  }

  return value === undefined ? { args: nextArgs } : { args: nextArgs, value };
}

function readOption(args: readonly string[], flag: string): string | undefined {
  const index = args.indexOf(flag);

  if (index === -1) {
    return undefined;
  }

  const value = args[index + 1];

  if (!value || value.startsWith('--')) {
    throw new Error(`Missing value for ${flag}.`);
  }

  return value;
}

function resolveStaticInvocation(
  args: readonly string[],
  loadedConfig: LoadedPrototype0Config | undefined,
): { targetPaths: string[]; remainingArgs: string[] } {
  const [firstArg, ...remainingArgs] = args;

  if (firstArg && !firstArg.startsWith('--')) {
    return {
      targetPaths: [path.resolve(firstArg)],
      remainingArgs,
    };
  }

  const configuredTargets = resolveConfiguredStaticTargets(loadedConfig);

  if (configuredTargets.length > 0) {
    return {
      targetPaths: configuredTargets,
      remainingArgs: [...args],
    };
  }

  return {
    targetPaths: [path.resolve('.')],
    remainingArgs: [...args],
  };
}

function getEnabledStaticRules(
  loadedConfig: LoadedPrototype0Config | undefined,
): Rule[] {
  const rulesConfig = loadedConfig?.config.staticAnalysis?.rules;
  const enabledRules: Rule[] = [];

  if (rulesConfig?.domXss !== false) {
    enabledRules.push(domXssRule);
  }

  if (rulesConfig?.storage !== false) {
    enabledRules.push(storageRule);
  }

  if (rulesConfig?.thirdPartyScripts !== false) {
    enabledRules.push(thirdPartyScriptsRule);
  }

  return enabledRules;
}

async function collectStaticFiles(
  targetPaths: readonly string[],
  extensions: readonly string[] | undefined,
): Promise<string[]> {
  const collectedFiles = new Set<string>();

  for (const targetPath of targetPaths) {
    let filesForTarget: string[];

    try {
      filesForTarget = await collectSourceFiles(targetPath, { extensions });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);

      if (error instanceof Error && 'code' in error && error.code === 'ENOENT') {
        throw new Error(`Static scan target not found: ${targetPath}`);
      }

      throw new Error(`Could not read static scan target ${targetPath}: ${message}`);
    }

    for (const filePath of filesForTarget) {
      collectedFiles.add(filePath);
    }
  }

  return [...collectedFiles].sort();
}

async function scanStaticFiles(
  files: readonly string[],
  rules: readonly Rule[],
): Promise<Finding[]> {
  const allFindings: Finding[] = [];

  for (const filePath of files) {
    try {
      const code = await fs.readFile(filePath, 'utf8');
      const findings = isHtmlFile(filePath)
        ? scanHtmlFile(filePath, code, rules)
        : scanStandardStaticFile(filePath, code, rules);

      allFindings.push(...findings);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : 'Unknown parsing error';

      allFindings.push({
        ruleId: 'PARSER_ERROR',
        severity: 'LOW',
        message,
        filePath,
      });
    }
  }

  return allFindings;
}

function scanStandardStaticFile(
  filePath: string,
  code: string,
  rules: readonly Rule[],
): Finding[] {
  const ast = isJavaScriptLikeFile(filePath) ? parseSource(code, filePath) : null;

  return runRules(
    { filePath, code, ast },
    [...rules],
  );
}

function scanHtmlFile(
  filePath: string,
  code: string,
  rules: readonly Rule[],
): Finding[] {
  const findings = runRules(
    { filePath, code, ast: null },
    [...rules],
  );

  const inlineScriptBlocks = extractInlineScriptBlocks(code);

  for (const block of inlineScriptBlocks) {
    try {
      const ast = parseSource(block.code, filePath, {
        startLine: block.startLine,
        startColumn: block.startColumn,
      });

      const inlineFindings = runRules(
        { filePath, code: block.code, ast },
        [...rules],
      ).map((finding) => ({
        ...finding,
        inlineScriptBlockIndex: block.blockIndex,
      }));

      findings.push(...inlineFindings);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown parsing error';
      const parserMessage = message.split(/\r?\n/, 1)[0] ?? message;

      findings.push({
        ruleId: 'PARSER_ERROR',
        severity: 'LOW',
        message: `Inline script block #${block.blockIndex} parse error: ${parserMessage}`,
        filePath,
        line: block.startLine,
        column: block.startColumn,
        inlineScriptBlockIndex: block.blockIndex,
      });
    }
  }

  return findings;
}

function getStaticOutputPath(
  args: readonly string[],
  loadedConfig: LoadedPrototype0Config | undefined,
): string | undefined {
  return readOption(args, '--output') ?? resolveConfiguredOutputPath(loadedConfig, 'staticReport');
}

function getDynamicOutputPath(
  args: readonly string[],
  loadedConfig: LoadedPrototype0Config | undefined,
): string | undefined {
  return readOption(args, '--output') ?? resolveConfiguredOutputPath(loadedConfig, 'dynamicReport');
}

function getCorrelationDefaults(loadedConfig: LoadedPrototype0Config | undefined): {
  defaultStaticPath?: string | undefined;
  defaultDynamicPath?: string | undefined;
  defaultOutputPath?: string | undefined;
  locationDistanceThreshold?: number | undefined;
} {
  return {
    defaultStaticPath: resolveConfiguredOutputPath(loadedConfig, 'staticReport'),
    defaultDynamicPath: resolveConfiguredOutputPath(loadedConfig, 'dynamicReport'),
    defaultOutputPath: resolveConfiguredOutputPath(loadedConfig, 'correlatedReport'),
    locationDistanceThreshold:
      loadedConfig?.config.correlation?.locationDistanceThreshold,
  };
}

function assertDynamicUrl(url: string): void {
  try {
    new URL(url);
  } catch {
    throw new Error(
      `Dynamic scan URL is invalid: ${url}. Use an absolute URL such as http://localhost:8080/.`,
    );
  }
}

function formatPathSummary(targetPaths: readonly string[]): string {
  if (targetPaths.length === 1) {
    return targetPaths[0] ?? '';
  }

  return targetPaths.join(', ');
}

async function handleStaticCommand(
  args: readonly string[],
  loadedConfig: LoadedPrototype0Config | undefined,
): Promise<number> {
  if (hasHelpFlag(args)) {
    printStaticUsage();
    return 0;
  }

  if (loadedConfig?.config.staticAnalysis?.enabled === false) {
    throw new Error('Static analysis is disabled in the config.');
  }

  const { targetPaths, remainingArgs } = resolveStaticInvocation(args, loadedConfig);
  const outputPath = getStaticOutputPath(remainingArgs, loadedConfig);
  const extensions = loadedConfig?.config.staticAnalysis?.extensions;
  const rules = getEnabledStaticRules(loadedConfig);
  const files = await collectStaticFiles(targetPaths, extensions);

  if (files.length === 0) {
    console.log('No source files found.');
    return 0;
  }

  const allFindings = await scanStaticFiles(files, rules);

  if (outputPath) {
    try {
      await writeStaticJsonReport(allFindings, formatPathSummary(targetPaths), outputPath);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(`Could not write static report to ${outputPath}: ${message}`);
    }

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
    return 0;
  }

  printFindings(allFindings);
  return 0;
}

async function handleDynamicCommand(
  args: readonly string[],
  loadedConfig: LoadedPrototype0Config | undefined,
): Promise<number> {
  if (hasHelpFlag(args)) {
    printDynamicUsage();
    return 0;
  }

  if (loadedConfig?.config.dynamicAnalysis?.enabled === false) {
    throw new Error('Dynamic analysis is disabled in the config.');
  }

  const commandArgs = args[0] === 'scan' ? args.slice(1) : args;
  const url = readOption(commandArgs, '--url') ?? getDefaultDynamicUrl(loadedConfig);
  const outputPath = getDynamicOutputPath(commandArgs, loadedConfig);
  const includeRawEvents =
    commandArgs.includes('--include-raw') ||
    (loadedConfig?.config.dynamicAnalysis?.includeRawEvents ?? false);
  const headless = commandArgs.includes('--headed')
    ? false
    : (loadedConfig?.config.dynamicAnalysis?.headless ?? true);
  const browserName: DynamicBrowserName =
    loadedConfig?.config.dynamicAnalysis?.browser ?? 'chromium';
  const timeoutMs = loadedConfig?.config.dynamicAnalysis?.timeoutMs;
  const postLoadWaitMs = loadedConfig?.config.dynamicAnalysis?.waitAfterLoadMs;

  if (!url) {
    console.error(
      'Dynamic scan URL is missing. Pass --url <target-url> or set targets.dynamicUrl in the config.',
    );
    printDynamicUsage();
    return 1;
  }

  assertDynamicUrl(url);

  try {
    const result = await runDynamicScan({
      url,
      browserName,
      headless,
      timeoutMs,
      postLoadWaitMs,
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

    if (error instanceof DynamicScanSetupError) {
      console.error(error.message);
      if (error.originalMessage) {
        console.error(`Details: ${error.originalMessage}`);
      }
      return 1;
    }

    if (error instanceof Error) {
      throw new Error(`Dynamic scan failed: ${error.message}`);
    }

    throw error;
  }
}

async function handleCorrelationCli(
  args: readonly string[],
  loadedConfig: LoadedPrototype0Config | undefined,
): Promise<number> {
  if (loadedConfig?.config.correlation?.enabled === false) {
    throw new Error('Correlation is disabled in the config.');
  }

  return handleCorrelationCommand(args, getCorrelationDefaults(loadedConfig));
}

async function main() {
  const rawArgs = process.argv.slice(2);
  const { args, value: explicitConfigPath } = consumeOption(rawArgs, '--config');
  const loadedConfig = await loadPrototype0Config({
    cwd: process.cwd(),
    explicitPath: explicitConfigPath,
  });

  const [firstArg, ...remainingArgs] = args;

  if (firstArg === 'help' || firstArg === '--help' || firstArg === '-h') {
    printMainUsage();
    return;
  }

  if (firstArg === 'dynamic') {
    process.exitCode = await handleDynamicCommand(remainingArgs, loadedConfig);
    return;
  }

  if (firstArg === 'correlate') {
    process.exitCode = await handleCorrelationCli(remainingArgs, loadedConfig);
    return;
  }

  process.exitCode = await handleStaticCommand(args, loadedConfig);
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(message);
  process.exit(1);
});
