import traverse from "@babel/traverse";
import type { AssignmentExpression, CallExpression, JSXAttribute, JSXOpeningElement, MemberExpression } from "@babel/types";
import { isIdentifier, isJSXIdentifier, isMemberExpression, isStringLiteral } from "@babel/types";

import { createFinding, type Finding, type RuleDefinition } from "../engine/findings.js";

function getMemberPropertyName(node: MemberExpression): string | undefined {
  if (isIdentifier(node.property)) {
    return node.property.name;
  }

  if (isStringLiteral(node.property)) {
    return node.property.value;
  }

  return undefined;
}

function getExternalSeverity(url: string): "medium" | "high" {
  return url.startsWith("http://") ? "high" : "medium";
}

function isExternalUrl(url: string): boolean {
  return /^https?:\/\//i.test(url) || url.startsWith("//");
}

export const thirdPartyScriptsRule: RuleDefinition = {
  id: "third-party-scripts",
  title: "Third-Party Script Load",
  description: "Flags direct loading of external script resources.",
  run({ file }) {
    const findings: Finding[] = [];

    traverse(file.ast, {
      JSXOpeningElement(path: { node: JSXOpeningElement }) {
        if (!isJSXIdentifier(path.node.name) || path.node.name.name !== "script") {
          return;
        }

        for (const attribute of path.node.attributes) {
          if (attribute.type !== "JSXAttribute") {
            continue;
          }

          const srcAttribute = attribute as JSXAttribute;

          if (!isJSXIdentifier(srcAttribute.name) || srcAttribute.name.name !== "src") {
            continue;
          }

          if (srcAttribute.value?.type !== "StringLiteral" || !isExternalUrl(srcAttribute.value.value)) {
            continue;
          }

          findings.push(
            createFinding(
              thirdPartyScriptsRule,
              file.filePath,
              getExternalSeverity(srcAttribute.value.value),
              `External script loaded from ${srcAttribute.value.value}.`,
              srcAttribute,
              srcAttribute.value.value,
            ),
          );
        }
      },
      AssignmentExpression(path: { node: AssignmentExpression }) {
        if (!isMemberExpression(path.node.left)) {
          return;
        }

        const property = getMemberPropertyName(path.node.left);

        if (property !== "src" || !isStringLiteral(path.node.right) || !isExternalUrl(path.node.right.value)) {
          return;
        }

        findings.push(
          createFinding(
            thirdPartyScriptsRule,
            file.filePath,
            getExternalSeverity(path.node.right.value),
            `Script source is assigned an external URL: ${path.node.right.value}.`,
            path.node,
            path.node.right.value,
          ),
        );
      },
      CallExpression(path: { node: CallExpression }) {
        if (!isMemberExpression(path.node.callee)) {
          return;
        }

        const property = getMemberPropertyName(path.node.callee);
        const firstArg = path.node.arguments[0];
        const secondArg = path.node.arguments[1];

        if (
          property !== "setAttribute" ||
          !firstArg ||
          !secondArg ||
          !isStringLiteral(firstArg) ||
          !isStringLiteral(secondArg) ||
          firstArg.value !== "src" ||
          !isExternalUrl(secondArg.value)
        ) {
          return;
        }

        findings.push(
          createFinding(
            thirdPartyScriptsRule,
            file.filePath,
            getExternalSeverity(secondArg.value),
            `setAttribute("src", ...) loads an external script from ${secondArg.value}.`,
            path.node,
            secondArg.value,
          ),
        );
      },
    });

    return findings;
  },
};
