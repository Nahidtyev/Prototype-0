export const TAINT_SOURCES = new Set([
  "location.search",
  "location.hash",
  "location.href",
  "window.location.search",
  "window.location.hash",
  "window.location.href",
  "document.URL",
  "document.cookie",
  "document.referrer",
  "window.name",
]);