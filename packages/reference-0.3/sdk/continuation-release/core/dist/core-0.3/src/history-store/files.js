/** Trusted local filesystem, cooperative writers. No network filesystem or hostile-admin guarantee. */
import * as fs from 'node:fs';
import { join, resolve, dirname, basename } from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { hostname } from 'node:os';
import { fail, exact, integer, uuid, json, parse } from "./codec.js";
export const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
export function directory(path) {
    if (typeof path !== 'string' || !path || path.length > 4096)
        fail('PATH_INVALID');
    const full = resolve(path), info = fs.lstatSync(full);
    if (!info.isDirectory() || info.isSymbolicLink() || (info.mode & 0o022) ||
        (process.getuid && info.uid !== process.getuid()))
        fail('PATH_INVALID');
    return fs.realpathSync(full);
}
export function fileInfo(path, max) {
    const s = fs.lstatSync(path);
    if (!s.isFile() || s.isSymbolicLink() || s.nlink !== 1 || s.size > max || (s.mode & 0o022) || (process.getuid && s.uid !== process.getuid()))
        fail('FILE_INVALID');
    return s;
}
export function read(path, max) {
    directory(dirname(path));
    const before = fileInfo(path, max), fd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    try {
        const info = fs.fstatSync(fd);
        if (info.ino !== before.ino || info.dev !== before.dev || info.size !== before.size)
            fail('FILE_CHANGED');
        const bytes = Buffer.alloc(info.size);
        let offset = 0;
        while (offset < bytes.length) {
            const n = fs.readSync(fd, bytes, offset, bytes.length - offset, offset);
            if (!n)
                fail('FILE_CHANGED');
            offset += n;
        }
        const after = fs.fstatSync(fd), current = fileInfo(path, max);
        if (after.size !== info.size || after.mtimeMs !== info.mtimeMs || current.ino !== info.ino || current.dev !== info.dev || current.size !== info.size)
            fail('FILE_CHANGED');
        return bytes;
    }
    finally {
        fs.closeSync(fd);
    }
}
export const sync = (fd, label, h) => h.sync ? h.sync(fd, label) : fs.fsyncSync(fd);
export function syncDirectory(path, h = {}) {
    const fd = fs.openSync(directory(path), 'r');
    try {
        sync(fd, 'directory', h);
    }
    finally {
        fs.closeSync(fd);
    }
}
export function writeNew(path, bytes, h = {}) {
    directory(dirname(path));
    const fd = fs.openSync(path, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    try {
        let offset = 0;
        while (offset < bytes.length) {
            const n = h.write ? h.write(fd, bytes, offset, bytes.length - offset) : fs.writeSync(fd, bytes, offset, bytes.length - offset);
            if (!Number.isSafeInteger(n) || n <= 0 || n > bytes.length - offset)
                fail('WRITE_FAILED');
            offset += n;
        }
        sync(fd, 'file', h);
    }
    finally {
        fs.closeSync(fd);
    }
}
export function writeImmutable(path, bytes, h = {}) {
    try {
        writeNew(path, bytes, h);
    }
    catch (e) {
        if (e.code !== 'EEXIST')
            throw e;
        if (!read(path, bytes.length).equals(bytes))
            fail('EXISTING_CONTENT_MISMATCH');
        const fd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
        try {
            sync(fd, 'file', h);
        }
        finally {
            fs.closeSync(fd);
        }
    }
    syncDirectory(dirname(path), h);
}
export const rename = (from, to, h = {}) => h.rename ? h.rename(from, to) : fs.renameSync(from, to);
export function lockRecord(path) {
    const bytes = read(path, 4096), record = parse(bytes);
    exact(record, ['version', 'host', 'pid', 'nonce']);
    if (record.version !== 'continuity-writer-lock/1' || typeof record.host !== 'string' || record.host.length > 256 || !integer(record.pid, 0x7fffffff) || record.pid === 0 || !uuid(record.nonce))
        fail('LOCK_UNVERIFIABLE');
    return Object.freeze({ bytes, record, sha256: sha(bytes) });
}
export function withLock(dir, callback, h = {}, lockName = '.writer-lock') {
    if (basename(lockName) !== lockName)
        fail('PATH_INVALID');
    directory(dir);
    const path = join(dir, lockName), guard = join(dir, lockName + '.recovery');
    try {
        writeNew(path, json({ version: 'continuity-writer-lock/1', host: hostname(), pid: process.pid, nonce: randomUUID() }));
    }
    catch (e) {
        if (e.code === 'EEXIST')
            fail('STORE_BUSY');
        throw e;
    }
    try {
        syncDirectory(dir);
        if (fs.existsSync(guard))
            fail('STORE_BUSY');
        h.point?.('lock-acquired');
        const result = callback();
        if (result && typeof result.then === 'function')
            fail('ASYNC_WRITER_FORBIDDEN');
        return result;
    }
    finally {
        fs.unlinkSync(path);
        syncDirectory(dir);
    }
}
/** Exact record + same recorded hostname + OS-confirmed absent PID; age is irrelevant. */
export function recoverLock(dir, expectedSha256, lockName = '.writer-lock') {
    if (basename(lockName) !== lockName)
        fail('PATH_INVALID');
    directory(dir);
    const guard = join(dir, lockName + '.recovery');
    try {
        writeNew(guard, json({ version: 'continuity-writer-lock/1', host: hostname(), pid: process.pid, nonce: randomUUID() }));
    }
    catch (e) {
        if (e.code === 'EEXIST')
            fail('RECOVERY_BUSY');
        throw e;
    }
    try {
        const path = join(dir, lockName), one = lockRecord(path);
        if (one.sha256 !== expectedSha256)
            fail('LOCK_CHANGED');
        if (one.record.host !== hostname())
            fail('LOCK_OWNER_UNKNOWN');
        try {
            process.kill(one.record.pid, 0);
            fail('LOCK_OWNER_LIVE');
        }
        catch (e) {
            if (e.code !== 'ESRCH')
                throw e;
        }
        const two = lockRecord(path);
        if (two.sha256 !== one.sha256)
            fail('LOCK_CHANGED');
        fs.unlinkSync(path);
        syncDirectory(dir);
    }
    finally {
        fs.unlinkSync(guard);
        syncDirectory(dir);
    }
}
