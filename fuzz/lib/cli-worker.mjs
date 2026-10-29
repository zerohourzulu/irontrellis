/**
 * Child process for the `cli-args` target (started with `fork`): runs the irontrellis CLI's
 * `main(argv, io)` in-process for each IPC request `{argv, env, cwd}` and answers
 * `{code, stdout, stderr}`, or `{threw}` when `main` itself rejected (it must not:
 * every error becomes an exit code). A child, so that a hang or an unexpected
 * `process.exit` is observable; IPC, so that anything a command writes to the real
 * stdout (bypassing `io`, which would break `--json`'s one-document output) is seen
 * by the parent as stray output.
 */
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const { main } = await import(pathToFileURL(join(ROOT, 'packages/cli/dist/cli.js')).href);
const unhandled = [];
process.on('unhandledRejection', (reason) => { unhandled.push(String(reason?.stack ?? reason).slice(0, 400)); });
const BASE_ENV = { ...process.env };

process.on('message', async (request) => {
  for (const key of Object.keys(process.env)) if (!(key in BASE_ENV)) delete process.env[key];
  Object.assign(process.env, { NO_COLOR: '1' }, request.env ?? {});
  let stdout = '', stderr = '';
  let response;
  try {
    if (request.cwd) process.chdir(request.cwd);
    const code = await main(request.argv, { stdout: (text) => { stdout += text; }, stderr: (text) => { stderr += text; } });
    await new Promise((resolve) => setTimeout(resolve, 5));
    response = { code, stdout: stdout.slice(0, 200_000), stderr: stderr.slice(0, 20_000), unhandled: unhandled.splice(0) };
  } catch (error) {
    response = { threw: `${error?.name}: ${error?.message}`, stack: String(error?.stack ?? '').split('\n').slice(0, 5), stdout, stderr };
  }
  process.send({ id: request.id, response });
});
process.send({ ready: true });
