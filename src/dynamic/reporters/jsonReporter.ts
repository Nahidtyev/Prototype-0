import { mkdir, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';

import type { DynamicScanResult } from '../types.js';

export async function writeDynamicJsonReport(
  result: DynamicScanResult,
  outputPath: string,
): Promise<void> {
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, JSON.stringify(result, null, 2), 'utf8');
}