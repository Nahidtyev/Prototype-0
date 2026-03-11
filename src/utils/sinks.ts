export const HTML_SINK_PROPERTIES = ["innerHTML", "outerHTML", "srcdoc"] as const;
export const HTML_SINK_METHODS = ["insertAdjacentHTML", "write", "writeln"] as const;
export const STORAGE_APIS = ["localStorage", "sessionStorage"] as const;

export function isHtmlSinkProperty(value: string): boolean {
  return HTML_SINK_PROPERTIES.includes(value as (typeof HTML_SINK_PROPERTIES)[number]);
}

export function isHtmlSinkMethod(value: string): boolean {
  return HTML_SINK_METHODS.includes(value as (typeof HTML_SINK_METHODS)[number]);
}

export function isStorageApi(value: string): boolean {
  return STORAGE_APIS.includes(value as (typeof STORAGE_APIS)[number]);
}
