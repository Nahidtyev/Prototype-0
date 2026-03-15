import { createHash } from 'node:crypto';

import type {
  DynamicCategory,
  DynamicFinding,
  DynamicRuleId,
  DynamicSeverity,
  RawNetworkEvent,
  RawRuntimeEvent,
  ScriptRuntimeEvent,
  StorageRuntimeEvent,
} from '../types.js';

interface NormalizeInput {
  runtime: RawRuntimeEvent[];
  network: RawNetworkEvent[];
}

export function normalizeDynamicEvents(
  input: NormalizeInput,
): DynamicFinding[] {
  const findings: DynamicFinding[] = [];

  for (const runtimeEvent of input.runtime) {
    const finding = normalizeRuntimeEvent(runtimeEvent);
    if (finding) {
      findings.push(finding);
    }
  }

  for (const networkEvent of input.network) {
    const finding = normalizeNetworkEvent(networkEvent);
    if (finding) {
      findings.push(finding);
    }
  }

  return deduplicateFindings(findings);
}

function normalizeRuntimeEvent(
  event: RawRuntimeEvent,
): DynamicFinding | undefined {
  if (
    event.type === 'innerHTML' ||
    event.type === 'outerHTML' ||
    event.type === 'document.write' ||
    event.type === 'eval' ||
    event.type === 'Function'
  ) {
    return createFinding({
      ruleId: 'DOM_SINK_USAGE',
      category: 'DOM_XSS',
      severity: 'HIGH',
      message: `Runtime DOM sink usage detected: ${event.type}`,
      pageUrl: event.location.pageUrl,
      frameUrl: event.location.frameUrl,
      observedAt: event.timestamp,
      evidence: {
        sink: event.type,
        valuePreview: event.valuePreview,
        stack: event.location.stack,
      },
      correlationParts: [
        'DOM_SINK_USAGE',
        event.location.pageUrl,
        event.location.frameUrl ?? '',
        event.type,
        event.valuePreview ?? '',
      ],
      locationHint: firstStackLine(event.location.stack),
    });
  }

  if (
    event.type === 'localStorage.setItem' ||
    event.type === 'sessionStorage.setItem'
  ) {
    const storageEvent = event as StorageRuntimeEvent;

    return createFinding({
      ruleId: 'BROWSER_STORAGE_WRITE',
      category: 'INSECURE_STORAGE',
      severity: 'MEDIUM',
      message: `Browser storage write detected: ${storageEvent.type}`,
      pageUrl: storageEvent.location.pageUrl,
      frameUrl: storageEvent.location.frameUrl,
      observedAt: storageEvent.timestamp,
      evidence: {
        storage: storageEvent.type.startsWith('localStorage')
          ? 'localStorage'
          : 'sessionStorage',
        key: storageEvent.key,
        valuePreview: storageEvent.valuePreview,
        stack: storageEvent.location.stack,
      },
      correlationParts: [
        'BROWSER_STORAGE_WRITE',
        storageEvent.location.pageUrl,
        storageEvent.location.frameUrl ?? '',
        storageEvent.type,
        storageEvent.key ?? '',
      ],
      locationHint: firstStackLine(storageEvent.location.stack),
    });
  }

  if (
    event.type === 'script.create' ||
    event.type === 'script.appendChild' ||
    event.type === 'script.insertBefore'
  ) {
    const scriptEvent = event as ScriptRuntimeEvent;

    return createFinding({
      ruleId: 'DYNAMIC_SCRIPT_CREATION',
      category: 'THIRD_PARTY_SCRIPT',
      severity: scriptEvent.isExternal ? 'HIGH' : 'MEDIUM',
      message: `Dynamic script activity detected: ${scriptEvent.type}`,
      pageUrl: scriptEvent.location.pageUrl,
      frameUrl: scriptEvent.location.frameUrl,
      observedAt: scriptEvent.timestamp,
      evidence: {
        action: scriptEvent.type,
        src: scriptEvent.src,
        isExternal: scriptEvent.isExternal,
        tagName: scriptEvent.tagName,
        stack: scriptEvent.location.stack,
      },
      correlationParts: [
        'DYNAMIC_SCRIPT_CREATION',
        scriptEvent.location.pageUrl,
        scriptEvent.location.frameUrl ?? '',
        scriptEvent.type,
        scriptEvent.src ?? '',
      ],
      locationHint: firstStackLine(scriptEvent.location.stack),
    });
  }

  if (event.type === 'script.src' || event.type === 'script.setAttribute.src') {
    const scriptEvent = event as ScriptRuntimeEvent;

    return createFinding({
      ruleId: 'SCRIPT_SRC_ASSIGNMENT',
      category: 'THIRD_PARTY_SCRIPT',
      severity: scriptEvent.isExternal ? 'HIGH' : 'MEDIUM',
      message: `Script source assignment detected: ${scriptEvent.type}`,
      pageUrl: scriptEvent.location.pageUrl,
      frameUrl: scriptEvent.location.frameUrl,
      observedAt: scriptEvent.timestamp,
      evidence: {
        action: scriptEvent.type,
        src: scriptEvent.src,
        isExternal: scriptEvent.isExternal,
        tagName: scriptEvent.tagName,
        stack: scriptEvent.location.stack,
      },
      correlationParts: [
        'SCRIPT_SRC_ASSIGNMENT',
        scriptEvent.location.pageUrl,
        scriptEvent.location.frameUrl ?? '',
        event.type,
        scriptEvent.src ?? '',
      ],
      locationHint: firstStackLine(scriptEvent.location.stack),
    });
  }

  return undefined;
}

function normalizeNetworkEvent(
  event: RawNetworkEvent,
): DynamicFinding | undefined {
  if (!event.isExternal) {
    return undefined;
  }

  return createFinding({
    ruleId: 'EXTERNAL_SCRIPT_LOAD',
    category: 'THIRD_PARTY_SCRIPT',
    severity: 'HIGH',
    message: `External script load detected: ${event.requestUrl}`,
    pageUrl: event.pageUrl,
    frameUrl: event.frameUrl,
    observedAt: event.timestamp,
    evidence: {
      requestUrl: event.requestUrl,
      method: event.method,
      resourceType: event.resourceType,
      isExternal: event.isExternal,
    },
    correlationParts: [
      'EXTERNAL_SCRIPT_LOAD',
      event.pageUrl,
      event.frameUrl ?? '',
      event.requestUrl,
    ],
    locationHint: event.requestUrl,
  });
}

function createFinding(params: {
  ruleId: DynamicRuleId;
  category: DynamicCategory;
  severity: DynamicSeverity;
  message: string;
  pageUrl: string;
  frameUrl?: string | undefined;
  observedAt: string;
  evidence: Record<string, unknown>;
  correlationParts: string[];
  locationHint?: string | undefined;
}): DynamicFinding {
  const fingerprint = hash(params.correlationParts.join('|'));

  return {
    id: `dynamic-${fingerprint}`,
    source: 'dynamic',
    ruleId: params.ruleId,
    category: params.category,
    severity: params.severity,
    message: params.message,
    pageUrl: params.pageUrl,
    frameUrl: params.frameUrl,
    observedAt: params.observedAt,
    evidence: params.evidence,
    correlation: {
      fingerprint,
      locationHint: params.locationHint,
    },
  };
}

function deduplicateFindings(findings: DynamicFinding[]): DynamicFinding[] {
  const uniqueFindings = new Map<string, DynamicFinding>();

  for (const finding of findings) {
    const deduplicationKey = `${finding.ruleId}:${finding.correlation.fingerprint}`;
    if (!uniqueFindings.has(deduplicationKey)) {
      uniqueFindings.set(deduplicationKey, finding);
    }
  }

  return [...uniqueFindings.values()];
}

function firstStackLine(stack?: string): string | undefined {
  if (!stack) {
    return undefined;
  }

  return stack
    .split('\n')
    .map((line) => line.trim())
    .find(Boolean);
}

function hash(value: string): string {
  return createHash('sha256').update(value).digest('hex').slice(0, 16);
}