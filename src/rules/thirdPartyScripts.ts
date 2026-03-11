import type { Rule } from "../engine/findings.js";

export const thirdPartyScriptsRule: Rule = {
  id: "THIRD_PARTY_SCRIPT",
  description: "Placeholder rule for third-party script risk detection",
  run() {
    return [];
  },
};