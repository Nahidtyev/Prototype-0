export function installStorageHooks(): void {
  type RuntimeEmitter = (event: unknown) => Promise<void> | void;

  type DynamicGlobal = Record<string, unknown> & {
    __DYNAMIC_STORAGE_HOOKS_INSTALLED__?: boolean;
    __dynamicRuntimeEmit?: RuntimeEmitter;
    location?: {
      href?: string;
    };
    localStorage?: unknown;
    sessionStorage?: unknown;
    Storage?: {
      prototype: Record<string, unknown>;
    };
  };

  const dynamicGlobal = globalThis as DynamicGlobal;

  if (dynamicGlobal.__DYNAMIC_STORAGE_HOOKS_INSTALLED__) {
    return;
  }

  dynamicGlobal.__DYNAMIC_STORAGE_HOOKS_INSTALLED__ = true;

  function emit(event: unknown): void {
    try {
      const runtimeEmitter = dynamicGlobal.__dynamicRuntimeEmit;
      if (typeof runtimeEmitter === 'function') {
        void runtimeEmitter(event);
      }
    } catch {
      // no-op
    }
  }

  function now(): string {
    return new Date().toISOString();
  }

  function preview(value: unknown, maxLength = 180): string | undefined {
    try {
      if (value === null || value === undefined) {
        return undefined;
      }

      const text =
        typeof value === 'string'
          ? value
          : typeof value === 'number' || typeof value === 'boolean'
            ? String(value)
            : JSON.stringify(value);

      if (!text) {
        return undefined;
      }

      return text.length > maxLength ? `${text.slice(0, maxLength)}...` : text;
    } catch {
      return '[unserializable]';
    }
  }

  function captureStack(): string | undefined {
    try {
      const stack = new Error().stack;
      if (!stack) {
        return undefined;
      }

      return stack
        .split('\n')
        .slice(2, 8)
        .map((line) => line.trim())
        .join('\n');
    } catch {
      return undefined;
    }
  }

  function getLocation(): {
    pageUrl: string;
    frameUrl?: string | undefined;
    stack?: string | undefined;
  } {
    const href = dynamicGlobal.location?.href ?? '';

    return {
      pageUrl: href,
      frameUrl: href || undefined,
      stack: captureStack(),
    };
  }

  function resolveStorageType(
    target: unknown,
  ): 'localStorage.setItem' | 'sessionStorage.setItem' | undefined {
    try {
      if (target === dynamicGlobal.localStorage) {
        return 'localStorage.setItem';
      }
    } catch {
      // no-op
    }

    try {
      if (target === dynamicGlobal.sessionStorage) {
        return 'sessionStorage.setItem';
      }
    } catch {
      // no-op
    }

    return undefined;
  }

  const StorageCtor = dynamicGlobal.Storage;
  if (!StorageCtor?.prototype) {
    return;
  }

  const originalSetItem = StorageCtor.prototype.setItem as
    | ((key: string, value: string) => void)
    | undefined;

  if (typeof originalSetItem !== 'function') {
    return;
  }

  StorageCtor.prototype.setItem = function patchedSetItem(
    this: unknown,
    key: string,
    value: string,
  ): void {
    const storageType = resolveStorageType(this);

    if (storageType) {
      emit({
        type: storageType,
        timestamp: now(),
        location: getLocation(),
        key,
        valuePreview: preview(value),
      });
    }

    originalSetItem.call(this, key, value);
  };
}