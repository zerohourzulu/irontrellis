#!/usr/bin/env node
// The `irontrellis` command. Everything lives in dist/cli.js (built with tsc).
import { main } from "../dist/cli.js";

// A closed pipe (`irontrellis … | head`) is not an error worth a stack trace.
const quietPipe = (error) => { if (error?.code === "EPIPE") process.exit(process.exitCode ?? 0); throw error; };
process.stdout.on("error", quietPipe);
process.stderr.on("error", quietPipe);

process.exitCode = await main(process.argv.slice(2));
