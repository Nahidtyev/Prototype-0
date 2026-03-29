import {
  type Browser,
  type BrowserContext,
  type BrowserType,
  type Page,
  type Request,
} from 'playwright';

import { installRuntimeHooks } from '../instrumentation/runtimeHooks.js';
import { installStorageHooks } from '../instrumentation/storageHooks.js';
import {
  REPORT_SCHEMA_VERSION,
  REPORT_TOOL_NAME,
} from '../../reporting/schema.js';
import { buildFindingSummary } from '../../reporting/summary.js';
import { writeDynamicJsonReport } from '../reporters/jsonReporter.js';
import { normalizeDynamicEvents } from './normalizer.js';
import type {
  DynamicBrowserName,
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

export class DynamicScanTargetUnreachableError extends Error {
  readonly targetUrl: string;
  readonly originalMessage: string;

  constructor(targetUrl: string, originalMessage: string) {
    super(
      `Dynamic scan could not reach ${formatTargetUrl(targetUrl)}. Make sure the target app is running.`,
    );
    this.name = 'DynamicScanTargetUnreachableError';
    this.targetUrl = targetUrl;
    this.originalMessage = originalMessage;
  }
}

export class DynamicScanSetupError extends Error {
  readonly originalMessage: string | undefined;

  constructor(message: string, originalMessage?: string) {
    super(message);
    this.name = 'DynamicScanSetupError';
    this.originalMessage = originalMessage;
  }
}

export async function runDynamicScan(
  options: DynamicScanOptions,
): Promise<DynamicScanResult> {
  const startedAt = new Date().toISOString();
  const runtimeEvents: RawRuntimeEvent[] = [];
  const networkEvents: RawNetworkEvent[] = [];
  const browserName = options.browserName ?? 'chromium';

  let browser: Browser | undefined;
  let context: BrowserContext | undefined;

  try {
    const browserType = await loadBrowserType(browserName);

    try {
      browser = await browserType.launch({
        headless: options.headless ?? true,
      });
    } catch (error) {
      throw toBrowserLaunchError(browserName, error);
    }

    if (!browser) {
      throw new DynamicScanSetupError(
        `Failed to launch the ${browserName} browser for dynamic scanning.`,
      );
    }

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

    try {
      await page.goto(options.url, {
        waitUntil: 'domcontentloaded',
        timeout: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
      });
    } catch (error) {
      if (isTargetUnreachableError(error)) {
        const originalMessage =
          error instanceof Error ? error.message : String(error);
        throw new DynamicScanTargetUnreachableError(options.url, originalMessage);
      }

      throw error;
    }

    await page.waitForTimeout(options.postLoadWaitMs ?? DEFAULT_POST_LOAD_WAIT_MS);

    const findings = normalizeDynamicEvents({
      runtime: runtimeEvents,
      network: networkEvents,
    });

    const finishedAt = new Date().toISOString();
    const summary = {
      ...buildFindingSummary(findings),
      rawRuntimeEventCount: runtimeEvents.length,
      rawNetworkEventCount: networkEvents.length,
    };

    const result: DynamicScanResult = {
      schemaVersion: REPORT_SCHEMA_VERSION,
      reportType: 'dynamic',
      metadata: {
        generatedAt: finishedAt,
        toolName: REPORT_TOOL_NAME,
        target: page.url(),
        startedAt,
        finishedAt,
        targetUrl: page.url(),
        browser: browserName,
        findingCount: findings.length,
      },
      summary,
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

    if (browser) {
      await browser.close().catch(() => undefined);
    }
  }
}

async function loadBrowserType(
  browserName: DynamicBrowserName,
): Promise<BrowserType<Browser>> {
  let playwright: typeof import('playwright');

  try {
    playwright = await import('playwright');
  } catch {
    throw new DynamicScanSetupError(
      'Playwright is not available. Run "npm install" to install project dependencies.',
    );
  }

  const browserType = playwright[browserName];

  if (!browserType || typeof browserType.launch !== 'function') {
    throw new DynamicScanSetupError(
      `Unsupported browser "${browserName}". Use chromium, firefox, or webkit.`,
    );
  }

  return browserType;
}

function toBrowserLaunchError(
  browserName: DynamicBrowserName,
  error: unknown,
): DynamicScanSetupError {
  const originalMessage = error instanceof Error ? error.message : String(error);
  const firstLine = originalMessage.split(/\r?\n/, 1)[0] ?? originalMessage;

  if (
    originalMessage.includes("Executable doesn't exist") ||
    originalMessage.includes('browserType.launch')
  ) {
    return new DynamicScanSetupError(
      `Playwright browser "${browserName}" is not installed or not available. Run "npx playwright install ${browserName}" and try again.`,
      firstLine,
    );
  }

  return new DynamicScanSetupError(
    `Failed to launch the ${browserName} browser for dynamic scanning.`,
    firstLine,
  );
}

function formatTargetUrl(value: string): string {
  try {
    return new URL(value).toString();
  } catch {
    return value;
  }
}

function isTargetUnreachableError(error: unknown): boolean {
  const message =
    error instanceof Error ? error.message : typeof error === 'string' ? error : '';

  if (!message.includes('page.goto')) {
    return false;
  }

  return [
    'ERR_CONNECTION_REFUSED',
    'ERR_CONNECTION_TIMED_OUT',
    'ERR_ADDRESS_UNREACHABLE',
    'ERR_NAME_NOT_RESOLVED',
    'ERR_INTERNET_DISCONNECTED',
    'ECONNREFUSED',
    'EHOSTUNREACH',
  ].some((token) => message.includes(token));
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
