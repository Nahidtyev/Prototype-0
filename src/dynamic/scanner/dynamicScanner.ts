import {
  chromium,
  type BrowserContext,
  type Page,
  type Request,
} from 'playwright';

import { installRuntimeHooks } from '../instrumentation/runtimeHooks.js';
import { installStorageHooks } from '../instrumentation/storageHooks.js';
import { writeDynamicJsonReport } from '../reporters/jsonReporter.js';
import { normalizeDynamicEvents } from './normalizer.js';
import type {
  DynamicScanOptions,
  DynamicScanResult,
  RawNetworkEvent,
  RawRuntimeEvent,
} from '../types.js';

const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_POST_LOAD_WAIT_MS = 2_000;

type RuntimeBindingSource = {
  page?: {
    url(): string;
  };
  frame?: {
    url(): string;
  };
};

export async function runDynamicScan(
  options: DynamicScanOptions,
): Promise<DynamicScanResult> {
  const startedAt = new Date().toISOString();
  const runtimeEvents: RawRuntimeEvent[] = [];
  const networkEvents: RawNetworkEvent[] = [];

  const browser = await chromium.launch({
    headless: options.headless ?? true,
  });

  let context: BrowserContext | undefined;

  try {
    context = await browser.newContext();

    await context.exposeBinding(
      '__dynamicRuntimeEmit',
      async (source: RuntimeBindingSource, payload: unknown) => {
        const sanitizedEvent = sanitizeRuntimeEvent(
          payload,
          source.page?.url(),
          source.frame?.url(),
        );

        if (sanitizedEvent) {
          runtimeEvents.push(sanitizedEvent);
        }
      },
    );

    await context.addInitScript({ content: `(${installRuntimeHooks.toString()})();` });
    await context.addInitScript({ content: `(${installStorageHooks.toString()})();` });

    const attachedPages = new WeakSet<Page>();

    const attachRequestListener = (page: Page): void => {
      if (attachedPages.has(page)) {
        return;
      }

      attachedPages.add(page);

      page.on('request', (request: Request) => {
        const networkEvent = toRawNetworkEvent(request, page);
        if (networkEvent) {
          networkEvents.push(networkEvent);
        }
      });
    };

    context.on('page', attachRequestListener);

    const page = await context.newPage();
    attachRequestListener(page);

    await page.goto(options.url, {
      waitUntil: 'domcontentloaded',
      timeout: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    });

    await page.waitForTimeout(options.postLoadWaitMs ?? DEFAULT_POST_LOAD_WAIT_MS);

    const findings = normalizeDynamicEvents({
      runtime: runtimeEvents,
      network: networkEvents,
    });

    const finishedAt = new Date().toISOString();

    const result: DynamicScanResult = {
      metadata: {
        startedAt,
        finishedAt,
        targetUrl: page.url(),
        browser: 'chromium',
      },
      findings,
      rawEvents: options.includeRawEvents
        ? {
            runtime: runtimeEvents,
            network: networkEvents,
          }
        : undefined,
    };

    if (options.outputPath) {
      await writeDynamicJsonReport(result, options.outputPath);
    }

    return result;
  } finally {
    if (context) {
      await context.close().catch(() => undefined);
    }

    await browser.close().catch(() => undefined);
  }
}

function sanitizeRuntimeEvent(
  payload: unknown,
  pageUrl?: string,
  frameUrl?: string,
): RawRuntimeEvent | undefined {
  if (!payload || typeof payload !== 'object') {
    return undefined;
  }

  const event = payload as Partial<RawRuntimeEvent> & {
    location?: {
      pageUrl?: string;
      frameUrl?: string;
      stack?: string;
    };
  };

  if (typeof event.type !== 'string') {
    return undefined;
  }

  const resolvedPageUrl = pageUrl || event.location?.pageUrl || '';
  const resolvedFrameUrl = frameUrl || event.location?.frameUrl || resolvedPageUrl;

  const sanitizedEvent: RawRuntimeEvent = {
    ...(event as RawRuntimeEvent),
    timestamp:
      typeof event.timestamp === 'string'
        ? event.timestamp
        : new Date().toISOString(),
    location: {
      pageUrl: resolvedPageUrl,
      frameUrl: resolvedFrameUrl || undefined,
      stack: event.location?.stack,
    },
  };

  if (isPlaywrightInternalRuntimeEvent(sanitizedEvent)) {
    return undefined;
  }

  return sanitizedEvent;
}

function toRawNetworkEvent(
  request: Request,
  page: Page,
): RawNetworkEvent | undefined {
  if (request.resourceType() !== 'script') {
    return undefined;
  }

  const requestUrl = request.url();
  const frameUrl = safeFrameUrl(request);
  const pageUrl = page.url() || frameUrl || '';

  return {
    type: 'external-script-request',
    timestamp: new Date().toISOString(),
    pageUrl,
    frameUrl: frameUrl || undefined,
    requestUrl,
    method: request.method(),
    resourceType: 'script',
    isExternal: isExternalUrl(requestUrl, frameUrl || pageUrl),
  };
}

function safeFrameUrl(request: Request): string | undefined {
  try {
    return request.frame()?.url();
  } catch {
    return undefined;
  }
}

function isExternalUrl(targetUrl: string, baseUrl: string): boolean {
  try {
    const target = new URL(targetUrl, baseUrl);
    const base = new URL(baseUrl);
    return target.origin !== base.origin;
  } catch {
    return false;
  }
}
function isPlaywrightInternalRuntimeEvent(event: RawRuntimeEvent): boolean {
  const stack = event.location.stack ?? '';
  const valuePreview =
    'valuePreview' in event && typeof event.valuePreview === 'string'
      ? event.valuePreview
      : '';

  const combined = `${stack}\n${valuePreview}`;

  return (
    combined.includes('__playwright__binding__controller__') ||
    combined.includes('UtilityScript.evaluate') ||
    combined.includes('__playwright__')
  );
}