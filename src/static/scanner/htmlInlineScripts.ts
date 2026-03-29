export interface InlineScriptBlock {
  blockIndex: number;
  code: string;
  startLine: number;
  startColumn: number;
}

const SCRIPT_TAG_REGEX = /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi;
const JAVASCRIPT_TYPES = new Set([
  '',
  'text/javascript',
  'application/javascript',
  'text/ecmascript',
  'application/ecmascript',
  'module',
]);

function getAttributeValue(attributes: string, name: string): string | undefined {
  const attributeRegex = new RegExp(
    `\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s"'=<>\\x60]+))`,
    'i',
  );
  const match = attributes.match(attributeRegex);

  return match?.[1] ?? match?.[2] ?? match?.[3];
}

function hasAttribute(attributes: string, name: string): boolean {
  const attributeRegex = new RegExp(`\\b${name}\\s*=`, 'i');
  return attributeRegex.test(attributes);
}

function isSupportedInlineScriptType(attributes: string): boolean {
  const type = getAttributeValue(attributes, 'type');

  if (!type) {
    return true;
  }

  return JAVASCRIPT_TYPES.has(type.trim().toLowerCase());
}

function getLineAndColumnForOffset(
  source: string,
  offset: number,
): { line: number; column: number } {
  const before = source.slice(0, offset);
  const lines = before.split(/\r\n|\n|\r/);
  const currentLine = lines[lines.length - 1] ?? '';

  return {
    line: lines.length,
    column: currentLine.length,
  };
}

export function extractInlineScriptBlocks(source: string): InlineScriptBlock[] {
  const blocks: InlineScriptBlock[] = [];
  let scriptTagIndex = 0;
  let match: RegExpExecArray | null;

  while ((match = SCRIPT_TAG_REGEX.exec(source)) !== null) {
    scriptTagIndex += 1;

    const attributes = match[1] ?? '';
    const content = match[2] ?? '';

    if (hasAttribute(attributes, 'src')) {
      continue;
    }

    if (!isSupportedInlineScriptType(attributes)) {
      continue;
    }

    if (content.trim().length === 0) {
      continue;
    }

    const fullMatch = match[0];
    const openTagEndIndex = fullMatch.indexOf('>');

    if (openTagEndIndex === -1) {
      continue;
    }

    const contentStartOffset = match.index + openTagEndIndex + 1;
    const { line, column } = getLineAndColumnForOffset(source, contentStartOffset);

    blocks.push({
      blockIndex: scriptTagIndex,
      code: content,
      startLine: line,
      startColumn: column,
    });
  }

  return blocks;
}
