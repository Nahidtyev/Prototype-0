import { stat } from "node:fs/promises";
import path from "node:path";

import fg from "fast-glob";

const DEFAULT_PATTERNS = ["**/*.{js,jsx,ts,tsx,mjs,cjs}"];
const DEFAULT_IGNORES = [
  "**/node_modules/**",
  "**/dist/**",
  "**/build/**",
  "**/coverage/**",
  "**/*.d.ts",
] as const;

export async function findSourceFiles(targetPath: string): Promise<string[]> {
  const resolvedPath = path.resolve(targetPath);
  const fileStats = await stat(resolvedPath);

  if (fileStats.isFile()) {
    return [resolvedPath];
  }

  return fg(DEFAULT_PATTERNS, {
    cwd: resolvedPath,
    absolute: true,
    onlyFiles: true,
    ignore: [...DEFAULT_IGNORES],
  });
}
