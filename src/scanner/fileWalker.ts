import fs from "node:fs/promises";
import path from "node:path";
import fg from "fast-glob";

const DEFAULT_PATTERNS = ["**/*.{js,jsx,ts,tsx}"];
const DEFAULT_IGNORE = [
  "**/node_modules/**",
  "**/dist/**",
  "**/.git/**",
  "**/coverage/**",
];

export async function collectSourceFiles(inputPath: string): Promise<string[]> {
  const resolvedPath = path.resolve(inputPath);
  const stats = await fs.stat(resolvedPath);

  if (stats.isFile()) {
    return [resolvedPath];
  }

  const files = await fg(DEFAULT_PATTERNS, {
    cwd: resolvedPath,
    absolute: true,
    onlyFiles: true,
    ignore: DEFAULT_IGNORE,
  });

  return files.sort();
}