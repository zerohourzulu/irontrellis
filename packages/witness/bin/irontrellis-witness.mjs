#!/usr/bin/env node
// The `irontrellis-witness` command. Everything lives in dist/cli.js (built with tsc).
import { main } from "../dist/cli.js";

// A closed pipe (`irontrellis-witness … | head`) is not an error worth a stack trace.
const quietPipe = (error) => { if (error?.code === "EPIPE") process.exit(process.exitCode ?? 0); throw error; };
process.stdout.on("error", quietPipe);
process.stderr.on("error", quietPipe);

const code = await main(process.argv.slice(2));
// `serve` keeps the process alive until a signal; every other command returns its exit code.
if (code !== undefined) process.exitCode = code;
