import { existsSync, readdirSync, copyFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
export function preserveHistories(directory) {
  const target = process.env.IRONTRELLIS_TEST_HISTORY_DIR;
  if (!target || !existsSync(directory)) return;
  mkdirSync(target, { recursive: true });
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) preserveHistories(path);
    else if (entry.name === 'history.jsonl') copyFileSync(path, join(target, randomUUID()+'.jsonl'));
  }
}
