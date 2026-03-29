import traverseImport from "@babel/traverse";
import * as t from "@babel/types";
import { createFinding, type Finding, type Rule } from "../engine/findings.js";
import { TAINT_SOURCES } from "../utils/sources.js";
import { DANGEROUS_CALLS, HTML_SINK_PROPERTIES } from "../utils/sinks.js";

const traverse: typeof traverseImport =
  typeof traverseImport === "function"
    ? traverseImport
    : (traverseImport as unknown as { default: typeof traverseImport }).default;

type TraverseVisitors = Parameters<typeof traverse>[1];
type VisitorPath<TNode extends t.Node> = Parameters<TraverseVisitors[string]>[0] & {
  node: TNode;
};

const TAINT_PRESERVING_STRING_METHODS = new Set(["slice", "substring", "trim"]);

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

function isSourceMemberExpression(node: t.Node): boolean {
  if (!t.isMemberExpression(node)) return false;

  const text = memberExpressionToString(node);
  return text !== null && TAINT_SOURCES.has(text);
}

function isTaintPreservingCallExpression(
  node: t.CallExpression,
  taintedVars: Set<string>,
): boolean {
  if (!t.isMemberExpression(node.callee)) {
    return false;
  }

  const propertyName = getMemberPropertyName(node.callee);
  if (!propertyName || !TAINT_PRESERVING_STRING_METHODS.has(propertyName)) {
    return false;
  }

  return isTainted(node.callee.object, taintedVars);
}

function isTainted(node: t.Node | null | undefined, taintedVars: Set<string>): boolean {
  if (!node) return false;

  if (t.isIdentifier(node)) {
    return taintedVars.has(node.name);
  }

  if (isSourceMemberExpression(node)) {
    return true;
  }

  if (t.isTemplateLiteral(node)) {
    return node.expressions.some((expr) => isTainted(expr, taintedVars));
  }

  if (t.isBinaryExpression(node)) {
    if (node.operator !== "+") {
      return false;
    }

    return isTainted(node.left, taintedVars) || isTainted(node.right, taintedVars);
  }

  if (t.isLogicalExpression(node)) {
    return isTainted(node.left, taintedVars) || isTainted(node.right, taintedVars);
  }

  if (t.isConditionalExpression(node)) {
    return (
      isTainted(node.test, taintedVars) ||
      isTainted(node.consequent, taintedVars) ||
      isTainted(node.alternate, taintedVars)
    );
  }

  if (t.isCallExpression(node)) {
    return isTaintPreservingCallExpression(node, taintedVars);
  }

  return false;
}

export const domXssRule: Rule = {
  id: "DOM_XSS",
  description: "Detects obvious DOM XSS source-to-sink patterns",
  run(context) {
    if (!context.ast) return [];

    const findings: Finding[] = [];
    const taintedVars = new Set<string>();

    traverse(context.ast, {
      VariableDeclarator(path: VisitorPath<t.VariableDeclarator>) {
        const { id, init } = path.node;

        if (t.isIdentifier(id) && isTainted(init, taintedVars)) {
          taintedVars.add(id.name);
        }
      },

      AssignmentExpression(path: VisitorPath<t.AssignmentExpression>) {
        const { left, right } = path.node;

        if (t.isIdentifier(left) && isTainted(right, taintedVars)) {
          taintedVars.add(left.name);
        }

        if (t.isMemberExpression(left)) {
          const propertyName = getMemberPropertyName(left);

          if (
            propertyName &&
            HTML_SINK_PROPERTIES.has(propertyName) &&
            isTainted(right, taintedVars)
          ) {
            findings.push(
              createFinding({
                ruleId: "DOM_XSS",
                severity: "HIGH",
                message: `Tainted data flows into ${propertyName}`,
                filePath: context.filePath,
                node: path.node,
              }),
            );
          }
        }
      },

      CallExpression(path: VisitorPath<t.CallExpression>) {
        const { callee, arguments: args } = path.node;

        if (t.isMemberExpression(callee)) {
          const calleeText = memberExpressionToString(callee);
          const propertyName = getMemberPropertyName(callee);

          if (calleeText && DANGEROUS_CALLS.has(calleeText)) {
            const firstArg = args[0];
            if (
              firstArg &&
              !t.isSpreadElement(firstArg) &&
              !t.isArgumentPlaceholder(firstArg) &&
              isTainted(firstArg, taintedVars)
            ) {
              findings.push(
                createFinding({
                  ruleId: "DOM_XSS",
                  severity: "HIGH",
                  message: `Tainted data reaches dangerous call ${calleeText}`,
                  filePath: context.filePath,
                  node: path.node,
                }),
              );
            }
          }

          if (propertyName === "insertAdjacentHTML") {
            const secondArg = args[1];
            if (
              secondArg &&
              !t.isSpreadElement(secondArg) &&
              !t.isArgumentPlaceholder(secondArg) &&
              isTainted(secondArg, taintedVars)
            ) {
              findings.push(
                createFinding({
                  ruleId: "DOM_XSS",
                  severity: "HIGH",
                  message: "Tainted data flows into insertAdjacentHTML",
                  filePath: context.filePath,
                  node: path.node,
                }),
              );
            }
          }
        }

        if (t.isIdentifier(callee) && callee.name === "eval") {
          const firstArg = args[0];
          if (
            firstArg &&
            !t.isSpreadElement(firstArg) &&
            !t.isArgumentPlaceholder(firstArg) &&
            isTainted(firstArg, taintedVars)
          ) {
            findings.push(
              createFinding({
                ruleId: "DOM_XSS",
                severity: "HIGH",
                message: "Tainted data reaches eval",
                filePath: context.filePath,
                node: path.node,
              }),
            );
          }
        }
      },

      NewExpression(path: VisitorPath<t.NewExpression>) {
        const { callee } = path.node;
        const args = path.node.arguments ?? [];

        if (t.isIdentifier(callee) && callee.name === "Function") {
          const hasTaintedArg = args.some((arg: (typeof args)[number]) => {
            if (t.isSpreadElement(arg) || t.isArgumentPlaceholder(arg)) return false;
            return isTainted(arg, taintedVars);
          });

          if (hasTaintedArg) {
            findings.push(
              createFinding({
                ruleId: "DOM_XSS",
                severity: "HIGH",
                message: "Tainted data reaches new Function",
                filePath: context.filePath,
                node: path.node,
              }),
            );
          }
        }
      },
    });

    return findings;
  },
};
