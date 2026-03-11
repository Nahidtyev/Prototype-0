import { readFile } from "node:fs/promises";

import { parse } from "@babel/parser";

import type { ParseFailure, ParsedFile } from "../engine/findings.js";

export async function parseFile(filePath: string): Promise<ParsedFile | ParseFailure> {
  const source = await readFile(filePath, "utf8");

  try {
    const ast = parse(source, {
      sourceType: "unambiguous",
      sourceFilename: filePath,
      errorRecovery: false,
      plugins: [
        "jsx",
        "typescript",
        "classProperties",
        "classPrivateProperties",
        "classPrivateMethods",
        "decorators-legacy",
        "dynamicImport",
      ],
    });

    return {
      filePath,
      source,
      ast,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown parse error";
    const location = typeof error === "object" && error && "loc" in error ? (error.loc as { line: number; column: number }) : undefined;

    const failure: ParseFailure = {
      filePath,
      message,
    };

    if (location) {
      failure.location = {
        line: location.line,
        column: location.column + 1,
      };
    }

    return failure;
  }
}

export function isParsedFile(value: ParsedFile | ParseFailure): value is ParsedFile {
  return "ast" in value;
}
