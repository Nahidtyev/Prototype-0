import traverse from "@babel/traverse";
import type { AssignmentExpression, CallExpression, Expression, MemberExpression } from "@babel/types";
import { isAssignmentExpression, isIdentifier, isMemberExpression, isStringLiteral } from "@babel/types";

import { createFinding, type Finding, type RuleDefinition } from "../engine/findings.js";
import { isSensitiveKeyName } from "../utils/sensitiveKeys..js";
import { isStorageApi } from "../utils/sinks.js";

function getMemberPropertyName(node: MemberExpression): string | undefined {
  if (isIdentifier(node.property)) {
    return node.property.name;
  }

  if (isStringLiteral(node.property)) {
    return node.property.value;
  }

  return undefined;
}

function getExpressionName(node: Expression): string | undefined {
  if (isIdentifier(node)) {
    return node.name;
  }

  if (isMemberExpression(node)) {
    const property = getMemberPropertyName(node);
    const object = node.object;

    if (isIdentifier(object) && property) {
      return `${object.name}.${property}`;
    }
  }

  return undefined;
}

export const storageRule: RuleDefinition = {
  id: "storage-secrets",
  title: "Sensitive Client Storage",
  description: "Flags probable secrets or session tokens written to browser storage.",
  run({ file }) {
    const findings: Finding[] = [];

    traverse(file.ast, {
      CallExpression(path: { node: CallExpression }) {
        if (!isMemberExpression(path.node.callee)) {
          return;
        }

        const target = path.node.callee.object;
        const method = getMemberPropertyName(path.node.callee);

        if (!isIdentifier(target) || !isStorageApi(target.name) || method !== "setItem") {
          return;
        }

        const keyArg = path.node.arguments[0];
        const keyName = keyArg && "type" in keyArg && isStringLiteral(keyArg) ? keyArg.value : undefined;

        if (!keyName || !isSensitiveKeyName(keyName)) {
          return;
        }

        findings.push(
          createFinding(
            storageRule,
            file.filePath,
            "medium",
            `Sensitive-looking key "${keyName}" is stored in ${target.name}.`,
            path.node,
            `${target.name}.setItem("${keyName}", ...)`,
          ),
        );
      },
      AssignmentExpression(path: { node: AssignmentExpression }) {
        if (!isAssignmentExpression(path.node) || !isMemberExpression(path.node.left)) {
          return;
        }

        const target = getExpressionName(path.node.left as Expression);

        if (target !== "document.cookie") {
          return;
        }

        findings.push(
          createFinding(
            storageRule,
            file.filePath,
            "medium",
            "document.cookie assignment may expose session or credential data to client-side code.",
            path.node,
            "document.cookie = ...",
          ),
        );
      },
    });

    return findings;
  },
};
