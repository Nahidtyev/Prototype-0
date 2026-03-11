const SENSITIVE_KEY_PATTERNS = [
  /token/i,
  /secret/i,
  /password/i,
  /passwd/i,
  /credential/i,
  /session/i,
  /cookie/i,
  /auth/i,
  /jwt/i,
  /api[-_]?key/i,
] as const;

export function isSensitiveKeyName(value: string): boolean {
  return SENSITIVE_KEY_PATTERNS.some((pattern) => pattern.test(value));
}
