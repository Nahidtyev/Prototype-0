export function installRuntimeHooks(): void {
  type RuntimeEmitter = (event: unknown) => Promise<void> | void;

  type DynamicGlobal = Record<string, unknown> & {
    __DYNAMIC_RUNTIME_HOOKS_INSTALLED__?: boolean;
    __dynamicRuntimeEmit?: RuntimeEmitter;
    location?: {
      href?: string;
    };
    eval?: (code: string) => unknown;
    Function?: FunctionConstructor;
    Element?: {
      prototype: Record<string, unknown>;
    };
    Document?: {
      prototype: Record<string, unknown>;
    };
    Node?: {
      prototype: Record<string, unknown>;
    };
    HTMLScriptElement?: {
      prototype: Record<string, unknown>;
    };
  };

  const dynamicGlobal = globalThis as DynamicGlobal;

  if (dynamicGlobal.__DYNAMIC_RUNTIME_HOOKS_INSTALLED__) {
    return;
  }

  dynamicGlobal.__DYNAMIC_RUNTIME_HOOKS_INSTALLED__ = true;

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

  function getHref(): string {
    try {
      return dynamicGlobal.location?.href ?? '';
    } catch {
      return '';
    }
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
    const href = getHref();

    return {
      pageUrl: href,
      frameUrl: href || undefined,
      stack: captureStack(),
    };
  }

  function absoluteUrl(value: string | undefined): string | undefined {
    if (!value) {
      return undefined;
    }

    try {
      return new URL(value, getHref()).href;
    } catch {
      return value;
    }
  }

  function isExternalUrl(value: string | undefined): boolean | undefined {
    if (!value) {
      return undefined;
    }

    try {
      const current = new URL(getHref());
      const target = new URL(value, getHref());
      return current.origin !== target.origin;
    } catch {
      return undefined;
    }
  }

  function isScriptElement(node: unknown): boolean {
    if (!node || typeof node !== 'object') {
      return false;
    }

    const tagName = (node as { tagName?: unknown }).tagName;
    return typeof tagName === 'string' && tagName.toUpperCase() === 'SCRIPT';
  }

  function getScriptResolvedSrc(scriptNode: unknown): string | undefined {
    if (!scriptNode || typeof scriptNode !== 'object') {
      return undefined;
    }

    const node = scriptNode as {
      src?: unknown;
      getAttribute?: (name: string) => string | null;
    };

    const directSrc =
      typeof node.src === 'string' && node.src.length > 0 ? node.src : undefined;

    const attrSrc =
      typeof node.getAttribute === 'function'
        ? node.getAttribute('src') ?? undefined
        : undefined;

    return absoluteUrl(directSrc ?? attrSrc);
  }

  function patchHtmlProperty(property: 'innerHTML' | 'outerHTML'): void {
    const ElementCtor = dynamicGlobal.Element;
    if (!ElementCtor?.prototype) {
      return;
    }

    const descriptor = Object.getOwnPropertyDescriptor(
      ElementCtor.prototype,
      property,
    );

    if (!descriptor?.get || !descriptor.set) {
      return;
    }

    const originalGet = descriptor.get as (this: unknown) => unknown;
    const originalSet = descriptor.set as (this: unknown, value: string) => void;

    Object.defineProperty(ElementCtor.prototype, property, {
      configurable: true,
      enumerable: descriptor.enumerable ?? false,
      get: originalGet,
      set(this: unknown, value: string) {
        emit({
          type: property,
          timestamp: now(),
          location: getLocation(),
          valuePreview: preview(value),
        });

        originalSet.call(this, value);
      },
    });
  }

  function patchDocumentWrite(): void {
    const DocumentCtor = dynamicGlobal.Document;
    if (!DocumentCtor?.prototype) {
      return;
    }

    const originalWrite = DocumentCtor.prototype.write as
      | ((...args: string[]) => void)
      | undefined;

    if (typeof originalWrite !== 'function') {
      return;
    }

    DocumentCtor.prototype.write = function patchedWrite(
      this: unknown,
      ...args: string[]
    ): void {
      emit({
        type: 'document.write',
        timestamp: now(),
        location: getLocation(),
        valuePreview: preview(args.join('')),
      });

      originalWrite.apply(this, args);
    };
  }

  function patchEval(): void {
    const originalEval = dynamicGlobal.eval;
    if (typeof originalEval !== 'function') {
      return;
    }

    dynamicGlobal.eval = function patchedEval(script: string): unknown {
      emit({
        type: 'eval',
        timestamp: now(),
        location: getLocation(),
        valuePreview: preview(script),
      });

      return originalEval.call(dynamicGlobal, script);
    };
  }

  function patchFunctionConstructor(): void {
    const OriginalFunction = dynamicGlobal.Function;
    if (typeof OriginalFunction !== 'function') {
      return;
    }

    const PatchedFunction = function patchedFunction(
      ...args: string[]
    ): Function {
      emit({
        type: 'Function',
        timestamp: now(),
        location: getLocation(),
        valuePreview: preview(args.join(', ')),
      });

      return OriginalFunction(...args);
    } as unknown as FunctionConstructor;

    dynamicGlobal.Function = PatchedFunction;
  }

  function patchCreateElement(): void {
    const DocumentCtor = dynamicGlobal.Document;
    if (!DocumentCtor?.prototype) {
      return;
    }

    const originalCreateElement = DocumentCtor.prototype.createElement as
      | ((tagName: string, options?: unknown) => unknown)
      | undefined;

    if (typeof originalCreateElement !== 'function') {
      return;
    }

    DocumentCtor.prototype.createElement = function patchedCreateElement(
      this: unknown,
      tagName: string,
      options?: unknown,
    ): unknown {
      const createdElement = originalCreateElement.call(this, tagName, options);

      if (String(tagName).toLowerCase() === 'script') {
        emit({
          type: 'script.create',
          timestamp: now(),
          location: getLocation(),
          tagName: 'SCRIPT',
        });
      }

      return createdElement;
    };
  }

  function patchScriptSrcSetter(): void {
    const HTMLScriptElementCtor = dynamicGlobal.HTMLScriptElement;
    if (!HTMLScriptElementCtor?.prototype) {
      return;
    }

    const descriptor = Object.getOwnPropertyDescriptor(
      HTMLScriptElementCtor.prototype,
      'src',
    );

    if (!descriptor?.get || !descriptor.set) {
      return;
    }

    const originalGet = descriptor.get as (this: unknown) => unknown;
    const originalSet = descriptor.set as (this: unknown, value: string) => void;

    Object.defineProperty(HTMLScriptElementCtor.prototype, 'src', {
      configurable: true,
      enumerable: descriptor.enumerable ?? false,
      get: originalGet,
      set(this: unknown, value: string) {
        const resolvedSrc = absoluteUrl(value);

        emit({
          type: 'script.src',
          timestamp: now(),
          location: getLocation(),
          src: resolvedSrc,
          isExternal: isExternalUrl(resolvedSrc),
          tagName: 'SCRIPT',
        });

        originalSet.call(this, value);
      },
    });
  }

  function patchSetAttribute(): void {
    const ElementCtor = dynamicGlobal.Element;
    if (!ElementCtor?.prototype) {
      return;
    }

    const originalSetAttribute = ElementCtor.prototype.setAttribute as
      | ((name: string, value: string) => void)
      | undefined;

    if (typeof originalSetAttribute !== 'function') {
      return;
    }

    ElementCtor.prototype.setAttribute = function patchedSetAttribute(
      this: unknown,
      name: string,
      value: string,
    ): void {
      const elementLike = this as { tagName?: unknown };

      if (
        typeof elementLike.tagName === 'string' &&
        elementLike.tagName.toUpperCase() === 'SCRIPT' &&
        name.toLowerCase() === 'src'
      ) {
        const resolvedSrc = absoluteUrl(value);

        emit({
          type: 'script.setAttribute.src',
          timestamp: now(),
          location: getLocation(),
          src: resolvedSrc,
          isExternal: isExternalUrl(resolvedSrc),
          tagName: 'SCRIPT',
        });
      }

      originalSetAttribute.call(this, name, value);
    };
  }

  function patchNodeInsertion(): void {
    const NodeCtor = dynamicGlobal.Node;
    if (!NodeCtor?.prototype) {
      return;
    }

    const originalAppendChild = NodeCtor.prototype.appendChild as
      | ((child: unknown) => unknown)
      | undefined;

    const originalInsertBefore = NodeCtor.prototype.insertBefore as
      | ((newNode: unknown, referenceNode: unknown) => unknown)
      | undefined;

    if (typeof originalAppendChild === 'function') {
      NodeCtor.prototype.appendChild = function patchedAppendChild(
        this: unknown,
        child: unknown,
      ): unknown {
        if (isScriptElement(child)) {
          const resolvedSrc = getScriptResolvedSrc(child);

          emit({
            type: 'script.appendChild',
            timestamp: now(),
            location: getLocation(),
            src: resolvedSrc,
            isExternal: isExternalUrl(resolvedSrc),
            tagName: 'SCRIPT',
          });
        }

        return originalAppendChild.call(this, child);
      };
    }

    if (typeof originalInsertBefore === 'function') {
      NodeCtor.prototype.insertBefore = function patchedInsertBefore(
        this: unknown,
        newNode: unknown,
        referenceNode: unknown,
      ): unknown {
        if (isScriptElement(newNode)) {
          const resolvedSrc = getScriptResolvedSrc(newNode);

          emit({
            type: 'script.insertBefore',
            timestamp: now(),
            location: getLocation(),
            src: resolvedSrc,
            isExternal: isExternalUrl(resolvedSrc),
            tagName: 'SCRIPT',
          });
        }

        return originalInsertBefore.call(this, newNode, referenceNode);
      };
    }
  }

  patchHtmlProperty('innerHTML');
  patchHtmlProperty('outerHTML');
  patchDocumentWrite();
  patchEval();
  patchFunctionConstructor();
  patchCreateElement();
  patchScriptSrcSetter();
  patchSetAttribute();
  patchNodeInsertion();
}