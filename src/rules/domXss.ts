import traverse from "@babel/traverse";
import type { AssignmentExpression, CallExpression, JSXAttribute, MemberExpression } from "@babel/types";
import { isIdentifier, isJSXIdentifier, isMemberExpression, isStringLiteral } from "@babel/types";

import { createFinding, type Finding, type RuleDefinition } from "../engine/findings.js";

const HTML_SINK_PROPERTIES = new Set(["innerHTML", "outerHTML", "srcdoc"]);
const HTML_SINK_METHODS = new Set(["insertAdjacentHTML", "write", "writeln"]);

function getMemberPropertyName(node: MemberExpression): string | undefined {
  if (isIdentifier(node.property)) {
    return node.property.name;
  }

  if (isStringLiteral(node.property)) {
    return node.property.value;
  }

  return undefined;
}

export const domXssRule: RuleDefinition = {
  id: "dom-xss",
  title: "DOM XSS sink usage",
  description: "Flags common HTML injection sinks.",
  run({ file }) {
    const findings: Finding[] = [];

    traverse(file.ast, {
      AssignmentExpression(path: { node: AssignmentExpression }) {
        if (!isMemberExpression(path.node.left)) {
          return;
        }

        const propertyName = getMemberPropertyName(path.node.left);

        if (!propertyName || !HTML_SINK_PROPERTIES.has(propertyName)) {
          return;
        }

        findings.push(
          createFinding(
            domXssRule,
            file.filePath,
            "high",
            `${propertyName} is used as an HTML injection sink.`,
            path.node,
            propertyName,
          ),
        );
      },
      CallExpression(path: { node: CallExpression }) {
        if (!isMemberExpression(path.node.callee)) {
          return;
        }

        const propertyName = getMemberPropertyName(path.node.callee);

        if (!propertyName || !HTML_SINK_METHODS.has(propertyName)) {
          return;
        }

        findings.push(
          createFinding(
            domXssRule,
            file.filePath,
            "high",
            `${propertyName}() writes raw HTML into the DOM.`,
            path.node,
            propertyName,
          ),
        );
      },
      JSXAttribute(path: { node: JSXAttribute }) {
        if (!isJSXIdentifier(path.node.name) || path.node.name.name !== "dangerouslySetInnerHTML") {
          return;
        }

        findings.push(
          createFinding(
            domXssRule,
            file.filePath,
            "high",
            "dangerouslySetInnerHTML bypasses React escaping.",
            path.node,
            "dangerouslySetInnerHTML",
          ),
        );
      },
    });

    return findings;
  },
};
