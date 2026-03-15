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
}): Finding {
  const finding: Finding = {
    ruleId: params.ruleId,
    severity: params.severity,
    message: params.message,
    filePath: params.filePath,
  };

  if (params.node?.loc) {
    finding.line = params.node.loc.start.line;
    finding.column = params.node.loc.start.column;
  }

  return finding;
}