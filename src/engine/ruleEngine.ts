import type { Finding, Rule, RuleContext } from "./findings.js";

export function runRules(context: RuleContext, rules: Rule[]): Finding[] {
  const findings: Finding[] = [];

  for (const rule of rules) {
    findings.push(...rule.run(context));
  }

  return findings;
}