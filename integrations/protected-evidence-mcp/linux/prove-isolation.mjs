#!/usr/bin/env node
// Explicit disposable Linux lab only: creates temporary users and synthetic
// files, runs two isolated identities, then removes only those resources.
import assert from "node:assert/strict";
import {
  mkdtempSync,
  mkdirSync,
  chmodSync,
  chownSync,
  rmSync,
  readFileSync,
} from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import { execFileSync, spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { createDemo } from "../setup.mjs";
if (
  process.platform !== "linux" ||
  process.getuid() !== 0 ||
  process.argv[2] !== "--run-disposable-lab"
)
  throw Error("Run explicitly as root on a disposable Linux development lab.");
const token = randomBytes(4).toString("hex"),
  brokerName = `itb${token}`,
  agentName = `ita${token}`;
const lab = mkdtempSync("/var/tmp/irontrellis-isolation-");
chmodSync(lab, 0o755);
const users = [],
  children = [],
  environment = {
    PATH: "/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    LANG: "C.UTF-8",
  };
const command = (name, args) =>
  execFileSync(name, args, { encoding: "utf8", env: environment });
const user = (name) => {
  command("useradd", [
    "--system",
    "--user-group",
    "--no-create-home",
    "--shell",
    "/usr/sbin/nologin",
    name,
  ]);
  users.push(name);
  return {
    uid: Number(command("id", ["-u", name])),
    gid: Number(command("id", ["-g", name])),
  };
};
const launch = (name, args) => {
  const child = spawn(
    "runuser",
    ["-u", name, "--", "setpriv", "--no-new-privs", process.execPath, ...args],
    { stdio: ["pipe", "pipe", "pipe"], env: environment, detached: true },
  );
  children.push(child);
  return child;
};
function lines(child) {
  const queue = [],
    waiters = [];
  createInterface({ input: child.stdout }).on("line", (line) => {
    const value = JSON.parse(line);
    const next = waiters.shift();
    if (next) next(value);
    else queue.push(value);
  });
  return () =>
    queue.length
      ? Promise.resolve(queue.shift())
      : new Promise((accept, reject) => {
          const timer = setTimeout(
            () => reject(Error("AGENT_RESPONSE_TIMEOUT")),
            15000,
          );
          waiters.push((value) => {
            clearTimeout(timer);
            accept(value);
          });
        });
}
try {
  const broker = user(brokerName),
    agent = user(agentName),
    demo = await createDemo(join(lab, "private"));
  command("chown", ["-R", `${broker.uid}:${broker.gid}`, join(lab, "private")]);
  const sockets = join(lab, "socket");
  mkdirSync(sockets, { mode: 0o755 });
  chownSync(sockets, broker.uid, broker.gid);
  const socketPath = join(sockets, "broker.sock");
  const brokerProcess = launch(brokerName, [
    fileURLToPath(new URL("./socket-server.mjs", import.meta.url)),
    demo.configFile,
    socketPath,
  ]);
  await new Promise((accept, reject) => {
    let text = "";
    const timer = setTimeout(
      () => reject(Error("BROKER_START_TIMEOUT")),
      10000,
    );
    brokerProcess.stderr.on("data", (bytes) => {
      text += bytes;
      if (text.includes("LOCAL_SOCKET_READY")) {
        clearTimeout(timer);
        accept();
      }
    });
    brokerProcess.on("exit", () => {
      clearTimeout(timer);
      reject(Error("BROKER_EXITED_BEFORE_READY"));
    });
  });
  chownSync(socketPath, broker.uid, agent.gid);
  chmodSync(socketPath, 0o660);
  const code = fileURLToPath(new URL("./socket-server.mjs", import.meta.url));
  const agentProcess = launch(agentName, [
    fileURLToPath(new URL("./agent-client.mjs", import.meta.url)),
    socketPath,
    demo.config.historyFile,
    demo.config.keyFile,
    join(demo.config.inputDirectory, "incident.txt"),
    code,
  ]);
  const next = lines(agentProcess),
    ready = await next();
  assert.equal(ready.ready, true);
  assert.equal(ready.isolation.uid, agent.uid);
  for (const [key, value] of Object.entries(ready.isolation))
    if (key !== "uid") assert.equal(value, true, key);
  agentProcess.stdin.write(
    JSON.stringify({ operationId: "linux:collection" }) + "\n",
  );
  const first = await next();
  assert.equal(first.status, "RECORDED");
  assert.equal(first.packetVerified, true);
  const before = demo.owner.exportHistory();
  assert.equal(
    before.filter((e) => e.type === "TRANSACTION_INTENT_CONSUMED").length,
    1,
  );
  await demo.owner.advanceEpoch({ agent: "bea", from: 1, to: 2 });
  assert.equal(brokerProcess.exitCode, null);
  assert.equal(agentProcess.exitCode, null);
  agentProcess.stdin.write(
    JSON.stringify({ operationId: "linux:obsolete" }) + "\n",
  );
  const refused = await next();
  assert.equal(refused.reason, "RUNTIME_NOT_CURRENT");
  agentProcess.stdin.write(
    JSON.stringify({ operationId: "linux:collection" }) + "\n",
  );
  const repeated = await next();
  assert.equal(repeated.status, "RECONCILIATION_ONLY");
  assert.equal(
    demo.owner
      .exportHistory()
      .filter((e) => e.type === "TRANSACTION_INTENT_CONSUMED").length,
    1,
  );
  assert.equal(
    readFileSync(join(demo.config.inputDirectory, "incident.txt"), "utf8"),
    "Synthetic example: unusual access requires review.\n",
  );
  console.log(
    JSON.stringify(
      {
        status: "PASS",
        platform: process.platform,
        node: process.version,
        brokerUid: broker.uid,
        agentUid: agent.uid,
        isolation: ready.isolation,
        first: first.status,
        oldLiveRuntime: refused.reason,
        retry: repeated.status,
        canonicalConsumptions: 1,
        scope:
          "Separate Linux identities protect this configured local resource, key, history and code; host administrator remains trusted. No network or general hostile-code sandbox claim.",
      },
      null,
      2,
    ),
  );
} finally {
  for (const child of children) {
    if (child.exitCode === null) {
      try {
        process.kill(-child.pid, "SIGTERM");
      } catch {}
    }
  }
  for (const child of children) {
    if (child.exitCode === null)
      await new Promise((accept) => {
        const timer = setTimeout(() => {
          try {
            process.kill(-child.pid, "SIGKILL");
          } catch {}
          accept();
        }, 3000);
        child.once("exit", () => {
          clearTimeout(timer);
          accept();
        });
      });
  }
  rmSync(lab, { recursive: true, force: true });
  for (const name of users.reverse()) command("userdel", [name]);
}
