#!/usr/bin/env node
// The `irontrellis-hook` command. Everything lives in dist/cli.js (built with tsc).
import { setDefaultVerifyThreads } from "@ramex-labs/irontrellis";
import { HOOK_VERIFY_THREADS, main } from "../dist/cli.js";

// Short-lived: one verification worker by default (IRONTRELLIS_VERIFY_THREADS still decides when set).
setDefaultVerifyThreads(HOOK_VERIFY_THREADS);

// A closed pipe is not an error worth a stack trace.
const quietPipe = (error) => { if (error?.code === "EPIPE") process.exit(process.exitCode ?? 0); throw error; };
process.stdout.on("error", quietPipe);
process.stderr.on("error", quietPipe);

process.exitCode = await main(process.argv.slice(2), { stdin: process.stdin, stdout: process.stdout, stderr: process.stderr, env: process.env, cwd: process.cwd() });
