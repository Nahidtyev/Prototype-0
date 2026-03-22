import traverseImport from "@babel/traverse";
import * as t from "@babel/types";
import { createFinding, type Finding, type Rule } from "../engine/findings.js";
import { isHtmlFile, isJavaScriptLikeFile, isRemoteUrl } from "../utils/urls.js";

const traverse: typeof traverseImport =
  typeof traverseImport === "function"
    ? traverseImport
    : (traverseImport as unknown as { default: typeof traverseImport }).default;

type TraverseVisitors = Parameters<typeof traverse>[1];
type VisitorPath<TNode extends t.Node> = Parameters<TraverseVisitors[string]>[0] & {
  node: TNode;
};

function getMemberPropertyName(node: t.MemberExpression): string | null {
  if (!node.computed && t.isIdentifier(node.property)) {
    return node.property.name;
  }

  if (node.computed && t.isStringLiteral(node.property)) {
    return node.property.value;
  }

  return null;
}

function memberExpressionToString(node: t.MemberExpression): string | null {
  const parts: string[] = [];
  let current: t.Expression | t.Super = node;

  while (t.isMemberExpression(current)) {
    const propertyName = getMemberPropertyName(current);
    if (!propertyName) return null;

    parts.unshift(propertyName);
    current = current.object;
  }

  if (t.isIdentifier(current)) {
    parts.unshift(current.name);
    return parts.join(".");
  }

  return null;
}

function getStringLiteralValue(node: t.Node | null | undefined): string | null {
  if (!node) return null;

  if (t.isStringLiteral(node)) {
    return node.value;
  }

  if (t.isTemplateLiteral(node) && node.expressions.length === 0) {
    return node.quasis.map((q) => q.value.cooked ?? "").join("");
  }

  return null;
}

function createJsFindings(context: Parameters<Rule["run"]>[0]): Finding[] {
  if (!context.ast) return [];

  const findings: Finding[] = [];
  const scriptVariables = new Set<string>();

  traverse(context.ast, {
    VariableDeclarator(path: VisitorPath<t.VariableDeclarator>) {
      const { id, init } = path.node;

      if (!t.isIdentifier(id) || !init) return;
      if (!t.isCallExpression(init)) return;

      const { callee, arguments: args } = init;

      if (!t.isMemberExpression(callee)) return;

      const calleeText = memberExpressionToString(callee);
      if (calleeText !== "document.createElement") return;

      const firstArg = args[0];
      if (!firstArg || t.isSpreadElement(firstArg) || t.isArgumentPlaceholder(firstArg)) {
        return;
      }

      const value = getStringLiteralValue(firstArg);
      if (value?.toLowerCase() === "script") {
        scriptVariables.add(id.name);
      }
    },

    AssignmentExpression(path: VisitorPath<t.AssignmentExpression>) {
      const { left, right } = path.node;

      if (!t.isMemberExpression(left)) return;
      if (!t.isIdentifier(left.object)) return;

      const variableName = left.object.name;
      const propertyName = getMemberPropertyName(left);

      if (!scriptVariables.has(variableName)) return;
      if (propertyName !== "src") return;

      const url = getStringLiteralValue(right);
      if (!url || !isRemoteUrl(url)) return;

      findings.push(
        createFinding({
          ruleId: "THIRD_PARTY_SCRIPT",
          severity: "MEDIUM",
          message: `Dynamically loads remote script from "${url}"`,
          filePath: context.filePath,
          node: path.node,
        }),
      );
    },

    CallExpression(path: VisitorPath<t.CallExpression>) {
      const { callee, arguments: args } = path.node;

      if (!t.isMemberExpression(callee)) return;
      if (!t.isIdentifier(callee.object)) return;

      const variableName = callee.object.name;
      const propertyName = getMemberPropertyName(callee);

      if (!scriptVariables.has(variableName)) return;
      if (propertyName !== "setAttribute") return;
      if (args.length < 2) return;

      const attrArg = args[0];
      const valueArg = args[1];

      if (
        !attrArg ||
        !valueArg ||
        t.isSpreadElement(attrArg) ||
        t.isArgumentPlaceholder(attrArg) ||
        t.isSpreadElement(valueArg) ||
        t.isArgumentPlaceholder(valueArg)
      ) {
        return;
      }

      const attrName = getStringLiteralValue(attrArg);
      const attrValue = getStringLiteralValue(valueArg);

      if (attrName?.toLowerCase() !== "src") return;
      if (!attrValue || !isRemoteUrl(attrValue)) return;

      findings.push(
        createFinding({
          ruleId: "THIRD_PARTY_SCRIPT",
          severity: "MEDIUM",
          message: `Dynamically sets remote script source "${attrValue}"`,
          filePath: context.filePath,
          node: path.node,
        }),
      );
    },
  });

  return findings;
}

function createHtmlFindings(context: Parameters<Rule["run"]>[0]): Finding[] {
  const findings: Finding[] = [];
  const scriptTagRegex = /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi;

  let match: RegExpExecArray | null;
  while ((match = scriptTagRegex.exec(context.code)) !== null) {
    const fullMatch = match[0];
    const src = match[1];

    if (!src || !isRemoteUrl(src)) continue;

    const hasIntegrity = /\bintegrity\s*=\s*["'][^"']+["']/i.test(fullMatch);
    if (hasIntegrity) continue;

    const before = context.code.slice(0, match.index);
    const line = before.split("\n").length;

    findings.push({
      ruleId: "THIRD_PARTY_SCRIPT",
      severity: "MEDIUM",
      message: `External script "${src}" is missing integrity attribute`,
      filePath: context.filePath,
      line,
      column: 0,
    });
  }

  return findings;
}

export const thirdPartyScriptsRule: Rule = {
  id: "THIRD_PARTY_SCRIPT",
  description: "Detects risky third-party script loading patterns",
  run(context) {
    if (isJavaScriptLikeFile(context.filePath)) {
      return createJsFindings(context);
    }

    if (isHtmlFile(context.filePath)) {
      return createHtmlFindings(context);
    }

    return [];
  },
};
