import traverseModule from "@babel/traverse";
import * as t from "@babel/types";
import { createFinding, type Finding, type Rule } from "../engine/findings.js";
import { SENSITIVE_STORAGE_KEYS } from "../utils/sensitiveKeys.js";

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

function isStorageTarget(callee: t.Node): boolean {
  if (!t.isMemberExpression(callee)) return false;

  const fullName = memberExpressionToString(callee);
  return (
    fullName === "localStorage.setItem" ||
    fullName === "sessionStorage.setItem" ||
    fullName === "window.localStorage.setItem" ||
    fullName === "window.sessionStorage.setItem"
  );
}

function getStringKey(node: t.Node | null | undefined): string | null {
  if (!node) return null;

  if (t.isStringLiteral(node)) {
    return node.value;
  }

  if (t.isTemplateLiteral(node) && node.expressions.length === 0) {
    return node.quasis.map((q) => q.value.cooked ?? "").join("");
  }

  return null;
}

export const storageRule: Rule = {
  id: "INSECURE_STORAGE",
  description: "Detects suspicious storage of sensitive data in browser storage",
  run(context) {
    const findings: Finding[] = [];

    const traverse =
      typeof traverseModule === "function"
        ? traverseModule
        : traverseModule.default;

    traverse(context.ast, {
      CallExpression(path) {
        const { callee, arguments: args } = path.node;

        if (!isStorageTarget(callee)) return;
        if (args.length < 2) return;

        const keyArg = args[0];
        if (t.isSpreadElement(keyArg) || t.isArgumentPlaceholder(keyArg)) return;

        const key = getStringKey(keyArg);
        if (!key) return;

        const normalizedKey = key.trim().toLowerCase();

        if (SENSITIVE_STORAGE_KEYS.has(normalizedKey)) {
          findings.push(
            createFinding({
              ruleId: "INSECURE_STORAGE",
              severity: "MEDIUM",
              message: `Sensitive value stored in browser storage under key "${key}"`,
              filePath: context.filePath,
              node: path.node,
            }),
          );
        }
      },
    });

    return findings;
  },
};