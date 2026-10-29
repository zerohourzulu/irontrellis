#!/usr/bin/env node
import { createServer } from "node:net";
import { chmodSync, existsSync } from "node:fs";
import { isAbsolute } from "node:path";
import { loadGateway } from "../config.mjs";
import { serveGateway } from "../server.mjs";
const [configFile, socketPath] = process.argv.slice(2);
if (!isAbsolute(socketPath ?? "") || existsSync(socketPath))
  throw Error(
    "Use a new absolute socket path in an operator-controlled directory.",
  );
const tool = loadGateway(configFile);
let active = false;
const server = createServer((socket) => {
  if (active) {
    socket.destroy();
    return;
  }
  active = true;
  const handle = serveGateway(tool, { input: socket, output: socket });
  socket.once("close", () => {
    handle.close().catch(() => {});
    active = false;
  });
  socket.on("error", () => {});
});
server.on("error", () => {
  process.stderr.write("LOCAL_SOCKET_UNAVAILABLE\n");
  process.exit(2);
});
server.listen(socketPath, () => {
  chmodSync(socketPath, 0o600);
  process.stderr.write("LOCAL_SOCKET_READY\n");
});
