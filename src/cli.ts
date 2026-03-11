import fs from "node:fs/promises";
import path from "node:path";
import { storageRule } from "./rules/storage.js";
import { collectSourceFiles } from "./scanner/fileWalker.js";
import { parseSource } from "./scanner/parser.js";
import { printFindings } from "./scanner/report.js";
import { runRules } from "./engine/ruleEngine.js";
import type { Finding } from "./engine/findings.js";
import { domXssRule } from "./rules/domXss.js";

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
      const ast = parseSource(code, filePath);

      const findings = runRules(
        { filePath, code, ast },
        [domXssRule, storageRule],
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

main().catch((error) => {
  console.error(error);
  process.exit(1);
});