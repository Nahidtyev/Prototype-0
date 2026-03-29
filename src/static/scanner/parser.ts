import { parse, type ParseResult } from "@babel/parser";
import type * as t from "@babel/types";

export interface ParseSourceOptions {
  startLine?: number | undefined;
  startColumn?: number | undefined;
  sourceFilename?: string | undefined;
}

export function parseSource(
  code: string,
  filePath: string,
  options: ParseSourceOptions = {},
): ParseResult<t.File> {
  return parse(code, {
    sourceType: "unambiguous",
    sourceFilename: options.sourceFilename ?? filePath,
    plugins: ["jsx", "typescript"],
    ...(options.startLine !== undefined ? { startLine: options.startLine } : {}),
    ...(options.startColumn !== undefined ? { startColumn: options.startColumn } : {}),
  });
}
