export const SOURCE_IDENTIFIERS = [
  "location",
  "document.URL",
  "document.documentURI",
  "document.location",
  "window.location",
  "location.href",
  "location.hash",
  "location.search",
  "document.cookie",
  "window.name",
  "postMessage",
  "localStorage",
  "sessionStorage",
] as const;

export function isKnownSourceName(value: string): boolean {
  return SOURCE_IDENTIFIERS.includes(value as (typeof SOURCE_IDENTIFIERS)[number]);
}
