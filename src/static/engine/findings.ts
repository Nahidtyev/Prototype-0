import type { ParseResult } from "@babel/parser";
import type * as t from "@babel/types";

export type Severity = "LOW" | "MEDIUM" | "HIGH";

export interface Finding {
  ruleId: string;
  severity: Severity;
  message: string;
  filePath: string;
  line?: number;
  column?: number;
  [key: string]: unknown;
}

export interface RuleContext {
  filePath: string;
  code: string;
  ast: ParseResult<t.File> | null;
}

export interface Rule {
  id: string;
  description: string;
  run(context: RuleContext): Finding[];
}

export function createFinding(params: {
  ruleId: string;
  severity: Severity;
  message: string;
  filePath: string;
  node?: t.Node;
} & Record<string, unknown>): Finding {
  const { ruleId, severity, message, filePath, node, ...extra } = params;

  const finding: Finding = {
    ruleId,
    severity,
    message,
    filePath,
    ...extra,
  };

  if (node?.loc) {
    finding.line = node.loc.start.line;
    finding.column = node.loc.start.column;
  }

  return finding;
}
