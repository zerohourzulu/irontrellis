#!/usr/bin/env python3
"""Bounded local vector runner. Exit 0=matched, 1=semantic mismatch, 2=execution/input error.

Adapted from Claude's abfaacd contribution. POSIX (macOS/Linux), Python3.9+.
Different harness language does not establish independent implementation correctness.
"""
from __future__ import annotations
import argparse
import json
import math
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent          # conformance/legacy
ROOT = HERE.parent.parent                       # repository root (adapter commands run from here)
FIXTURES = ROOT / 'packages' / 'reference-0.2' / 'tests' / 'fixtures'
LEVELS = {'verifier': {'replay', 'survives'}, 'evaluator': {'replay', 'survives', 'authorization'}}

class AdapterError(Exception):
    pass

def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result
    def constant(value):
        raise ValueError('non-finite JSON number')
    def finite_float(value):
        result = float(value)
        if not math.isfinite(result):
            raise ValueError('non-finite JSON number')
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant, parse_float=finite_float)

class Adapter:
    """Data/pipe bounds for a trusted local test program, not hostile-code isolation."""
    def __init__(self, command, timeout=10.0, max_response=1048576, max_request=8388608, max_stderr=65536):
        self.timeout, self.max_response = timeout, max_response
        self.max_request, self.max_stderr = max_request, max_stderr
        self.stderr = bytearray()
        self.buffer = bytearray()
        self.process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, bufsize=0)
        self.selector = selectors.DefaultSelector()
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            os.set_blocking(stream.fileno(), False)
        self.selector.register(self.process.stdout, selectors.EVENT_READ, 'stdout')
        self.selector.register(self.process.stderr, selectors.EVENT_READ, 'stderr')

    def ask(self, request):
        payload = json.dumps(request, allow_nan=False, separators=(',', ':')).encode() + b'\n'
        if len(payload) > self.max_request:
            raise AdapterError('REQUEST_LIMIT')
        if self.buffer:
            raise AdapterError('UNSOLICITED_OUTPUT')
        sent = 0
        deadline = time.monotonic() + self.timeout
        self.selector.register(self.process.stdin, selectors.EVENT_WRITE, 'stdin')
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AdapterError('TIMEOUT')
            ready = self.selector.select(remaining)
            for key, _ in ready:
                if key.data == 'stdin':
                    try:
                        sent += os.write(key.fd, payload[sent:sent + 65536])
                    except BrokenPipeError as error:
                        raise AdapterError('ADAPTER_CLOSED_INPUT') from error
                    if sent == len(payload):
                        self.selector.unregister(self.process.stdin)
                    continue
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    self.selector.unregister(key.fileobj)
                    if key.data == 'stdout':
                        raise AdapterError('ADAPTER_EOF')
                    continue
                if key.data == 'stderr':
                    if len(self.stderr) + len(chunk) > self.max_stderr:
                        raise AdapterError('STDERR_LIMIT')
                    self.stderr.extend(chunk)
                    continue
                self.buffer.extend(chunk)
                end = self.buffer.find(b'\n')
                if (end < 0 and len(self.buffer) > self.max_response) or end > self.max_response:
                    raise AdapterError('RESPONSE_LIMIT')
                if end >= 0:
                    if sent != len(payload):
                        raise AdapterError('RESPONSE_BEFORE_REQUEST_SENT')
                    raw = bytes(self.buffer[:end])
                    del self.buffer[:end + 1]
                    if self.buffer:
                        raise AdapterError('EXTRA_RESPONSE_DATA')
                    try:
                        answer = strict_json(raw.decode('utf-8'))
                    except (ValueError, RecursionError) as error:
                        raise AdapterError('INVALID_JSON') from error
                    if not isinstance(answer, dict) or type(answer.get('ok')) is not bool:
                        raise AdapterError('INVALID_ENVELOPE')
                    expected_keys = {'ok', 'result'} if answer['ok'] else {'ok', 'error'}
                    if set(answer) != expected_keys:
                        raise AdapterError('INVALID_ENVELOPE')
                    if answer['ok']:
                        if not isinstance(answer['result'], dict):
                            raise AdapterError('INVALID_RESULT')
                    else:
                        if not isinstance(answer['error'], str):
                            raise AdapterError('INVALID_ERROR')
                        raise AdapterError('ADAPTER_REPORTED_ERROR: ' + answer['error'][:200])
                    return answer

    def close(self):
        # Kill the owned group even if its leader exited leaving pipe holders.
        # Always reap/close local handles; a refused group kill remains an error.
        self.process.poll()  # Reap an exited leader before Darwin group signaling.
        try:
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except PermissionError:
                # The leader may exit between poll() and killpg(). Reap it,
                # then retry once: absence is fine, a live/refused group is not.
                if self.process.poll() is None:
                    raise
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        finally:
            try:
                self.process.wait(timeout=2)
            finally:
                self.selector.close()
                for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                    stream.close()


def differences(expected, actual, path=''):
    """Recursive declared-field projection; arrays/scalars and BigInt tags are exact."""
    label = path or '.'
    if type(expected) is not type(actual):
        return [f'{label}: expected {type(expected).__name__}, got {type(actual).__name__}']
    if isinstance(expected, dict):
        out = []
        if '$continuity.bigint' in expected and set(actual) != set(expected):
            out.append(f'{label}: tagged BigInt keys differ')
        for key, value in expected.items():
            child = f'{path}.{key}'
            if key not in actual:
                out.append(f'{child}: required field missing')
            else:
                out.extend(differences(value, actual[key], child))
        return out
    if isinstance(expected, list):
        if len(expected) != len(actual):
            return [f'{label}: expected {len(expected)} entries, got {len(actual)}']
        return [difference for i, (a, b) in enumerate(zip(expected, actual))
                for difference in differences(a, b, f'{path}[{i}]')]
    return [] if expected == actual else [f'{label}: expected {expected!r}, got {actual!r}']


def build_request(vector, histories):
    kind = vector['kind']
    if kind == 'replay':
        return {'op': 'replay', 'operationVersion': vector['input']['operationVersion'], 'events': vector['events']}
    if kind == 'authorization':
        return {'op': 'authorize', 'events': histories[vector['history']['ref']], **vector['input']}
    if kind == 'survives':
        return {'op': 'survives', 'events': histories[vector['history']['ref']][:vector['history']['eventCount']], **vector['input']}
    raise ValueError('unknown vector kind')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--level', choices=sorted(LEVELS), default='evaluator')
    parser.add_argument('--filter', default='')
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--timeout', type=float, default=10.0, help='seconds per request, including writes')
    parser.add_argument('--max-response-bytes', type=int, default=1048576)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    report = {'reportVersion': 'continuity-vector-report/1', 'level': args.level,
              'status': 'EXECUTION_ERROR', 'implementation': None, 'selected': 0,
              'passed': 0, 'mismatched': 0, 'errors': 0, 'notRun': [], 'results': []}
    adapter = None
    selected = []
    try:
        if not command or not math.isfinite(args.timeout) or not 0 < args.timeout <= 60:
            raise ValueError('command required; timeout must be finite, >0 and <=60 seconds')
        if not 64 <= args.max_response_bytes <= 16777216:
            raise ValueError('response byte limit must be 64..16777216')
        vectors = strict_json((HERE / 'vectors.json').read_text())
        fixtures = FIXTURES
        histories = {name: strict_json((fixtures / filename).read_text()) for name, filename in (
            ('first-look', 'handover-history.json'), ('no-review-power', 'handover-denied-history.json'),
            ('mandate', 'mandate-history.json'))}
        histories['mandate-quantitative-only'] = histories['mandate'][:6]
        selected = [v for v in vectors if v['kind'] in LEVELS[args.level] and args.filter in v['id']]
        if not selected:
            raise ValueError('NO_VECTORS_SELECTED')
        report['selected'] = len(selected)
        report['excluded'] = [v['id'] for v in vectors if v not in selected]
        adapter = Adapter(command, timeout=args.timeout, max_response=args.max_response_bytes)
        identity = adapter.ask({'op': 'describe'})['result']
        if not isinstance(identity.get('implementation'), str) or not identity['implementation']:
            raise AdapterError('INVALID_DESCRIPTION')
        report['implementation'] = identity
        for vector in selected:
            answer = adapter.ask(build_request(vector, histories))
            diff = differences(vector['expect'], answer['result'])
            result = {'id': vector['id'], 'status': 'MISMATCH' if diff else 'PASS'}
            if diff:
                result.update(differences=diff, purpose=vector['purpose'])
            report['results'].append(result)
        report['status'] = 'MISMATCH' if any(r['status'] == 'MISMATCH' for r in report['results']) else 'MATCH'
    except (OSError, ValueError, KeyError, TypeError, RecursionError, AdapterError) as error:
        report['errors'] = 1
        report['error'] = str(error)[:500]
    finally:
        if adapter:
            try:
                adapter.close()
            except (OSError, subprocess.TimeoutExpired) as error:
                report.update(status='EXECUTION_ERROR', errors=1, error='CLEANUP_FAILED: ' + str(error)[:200])
    completed = {r['id'] for r in report['results']}
    report['notRun'] = [v['id'] for v in selected if v['id'] not in completed]
    report['passed'] = sum(r['status'] == 'PASS' for r in report['results'])
    report['mismatched'] = sum(r['status'] == 'MISMATCH' for r in report['results'])
    if args.json:
        print(json.dumps(report, indent=2, allow_nan=False))
    else:
        print(f"{report['status']}: {report['passed']} matched, {report['mismatched']} mismatched, {report['errors']} execution errors, {len(report['notRun'])} not run")
        for result in report['results']:
            if result['status'] != 'PASS':
                print(result['id'], *result['differences'], sep='\n  ')
        if 'error' in report:
            print(report['error'])
        print('Finite selected-vector evidence, not full protocol certification or a second implementation.')
    return {'MATCH': 0, 'MISMATCH': 1, 'EXECUTION_ERROR': 2}[report['status']]

if __name__ == '__main__':
    sys.exit(main())
