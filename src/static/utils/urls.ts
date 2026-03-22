export function isRemoteUrl(value: string): boolean {
  const normalized = value.trim().toLowerCase();
  return (
    normalized.startsWith("http://") ||
    normalized.startsWith("https://") ||
    normalized.startsWith("//")
  );
}

export function isJavaScriptLikeFile(filePath: string): boolean {
  return /\.(js|jsx|ts|tsx)$/i.test(filePath);
}

export function isHtmlFile(filePath: string): boolean {
  return /\.html$/i.test(filePath);
}