import type { Rule } from "../engine/findings.js";

export const storageRule: Rule = {
  id: "INSECURE_STORAGE",
  description: "Placeholder rule for insecure browser storage detection",
  run() {
    return [];
  },
};