import { parse, type ParseResult } from "@babel/parser";
import type * as t from "@babel/types";

export function parseSource(code: string, filePath: string): ParseResult<t.File> {
  return parse(code, {
    sourceType: "unambiguous",
    sourceFilename: filePath,
    plugins: ["jsx", "typescript"],
  });
}