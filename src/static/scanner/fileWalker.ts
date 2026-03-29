import fs from "node:fs/promises";
import path from "node:path";
import fg from "fast-glob";

const DEFAULT_PATTERNS = ["**/*.{js,jsx,ts,tsx,html}"];
const DEFAULT_IGNORE = [
  "**/node_modules/**",
  "**/dist/**",
  "**/.git/**",
  "**/coverage/**",
];

export interface CollectSourceFilesOptions {
  extensions?: readonly string[] | undefined;
}

function normalizeExtensions(
  extensions: readonly string[] | undefined,
): string[] | undefined {
  if (!extensions) {
    return undefined;
  }

  const normalized = extensions
    .map((extension) => extension.trim().toLowerCase())
    .filter((extension) => extension.length > 0)
    .map((extension) => extension.replace(/^\./, ""));

  return [...new Set(normalized)];
}

function toGlobPatterns(
  extensions: readonly string[] | undefined,
): string[] {
  const normalized = normalizeExtensions(extensions);

  if (!normalized) {
    return DEFAULT_PATTERNS;
  }

  if (normalized.length === 0) {
    return [];
  }

  return [`**/*.{${normalized.join(",")}}`];
}

function matchesAllowedExtension(
  filePath: string,
  extensions: readonly string[] | undefined,
): boolean {
  const normalized = normalizeExtensions(extensions);

  if (!normalized) {
    return true;
  }

  if (normalized.length === 0) {
    return false;
  }

  const extension = path.extname(filePath).replace(/^\./, "").toLowerCase();
  return normalized.includes(extension);
}

export async function collectSourceFiles(
  inputPath: string,
  options: CollectSourceFilesOptions = {},
): Promise<string[]> {
  const resolvedPath = path.resolve(inputPath);
  const stats = await fs.stat(resolvedPath);

  if (stats.isFile()) {
    return matchesAllowedExtension(resolvedPath, options.extensions)
      ? [resolvedPath]
      : [];
  }

  const patterns = toGlobPatterns(options.extensions);
  if (patterns.length === 0) {
    return [];
  }

  const files = await fg(patterns, {
    cwd: resolvedPath,
    absolute: true,
    onlyFiles: true,
    ignore: DEFAULT_IGNORE,
  });

  return files.sort();
}
