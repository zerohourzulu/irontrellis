import { openSync, closeSync, fsyncSync, writeSync, readFileSync, lstatSync, realpathSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
export function writeNew(path, bytes) {
  const data = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  const fd = openSync(path, 'wx', 0o600);
  try {
    let offset = 0;
    while (offset < data.length) {
      const count = writeSync(fd, data, offset, data.length - offset);
      if (count < 1) throw new Error('WRITE_INCOMPLETE');
      offset += count;
    }
    fsyncSync(fd);
  } finally { closeSync(fd); }
  const parent = openSync(dirname(path), 'r');
  try { fsyncSync(parent); } finally { closeSync(parent); }
}
export function directory(path) {
  const absolute = resolve(path), info = lstatSync(absolute);
  if (!info.isDirectory() || info.isSymbolicLink() || realpathSync(absolute) !== absolute) throw new Error('DIRECTORY_MUST_NOT_BE_ALIASED');
  return absolute;
}
export function readJson(path, maximum = 1048576) {
  const info = lstatSync(path);
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.size > maximum) throw new Error('INVALID_LOCAL_JSON');
  return JSON.parse(readFileSync(path, 'utf8'));
}
