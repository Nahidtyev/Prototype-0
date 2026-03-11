import type { File, Node } from "@babel/types";

export type Severity = "low" | "medium" | "high";

export interface SourceLocation {
  line: number;
  column: number;
}

export interface Finding {
  ruleId: string;
  title: string;
  message: string;
  severity: Severity;
  filePath: string;
  location?: SourceLocation;
  snippet?: string;
}

export interface ParseFailure {
  filePath: string;
  message: string;
  location?: SourceLocation;
}

export interface ParsedFile {
  filePath: string;
  source: string;
  ast: File;
}

export interface RuleContext {
  file: ParsedFile;
}

export interface RuleDefinition {
  id: string;
  title: string;
  description: string;
  run(context: RuleContext): Finding[];
}

export function getNodeLocation(node: Node | null | undefined): SourceLocation | undefined {
  if (!node?.loc) {
    return undefined;
  }

  return {
    line: node.loc.start.line,
    column: node.loc.start.column + 1,
  };
}

export function createFinding(
  rule: Pick<RuleDefinition, "id" | "title">,
  filePath: string,
  severity: Severity,
  message: string,
  node?: Node | null,
  snippet?: string,
): Finding {
  const finding: Finding = {
    ruleId: rule.id,
    title: rule.title,
    message,
    severity,
    filePath,
  };

  const location = getNodeLocation(node);

  if (location) {
    finding.location = location;
  }

  if (snippet) {
    finding.snippet = snippet;
  }

  return finding;
}
