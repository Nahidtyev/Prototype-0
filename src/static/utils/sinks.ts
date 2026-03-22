export const HTML_SINK_PROPERTIES = new Set([
  "innerHTML",
  "outerHTML",
]);

export const DANGEROUS_CALLS = new Set([
  "document.write",
  "eval",
]);