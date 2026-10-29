#!/usr/bin/env node
// Runs as the unprivileged agent. Only forwards bytes to the operator socket.
import { connect } from "node:net";
const socket = connect(process.argv[2]);
process.stdin.pipe(socket);
socket.pipe(process.stdout);
socket.on("error", () => {
  process.stderr.write("SOCKET_UNAVAILABLE\n");
  process.exit(2);
});
socket.on("close", () => process.exit());
process.stdout.on("error", () => socket.destroy());
