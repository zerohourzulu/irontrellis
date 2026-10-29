// KNOWN-ISSUES r2.2 59: the gateway's reserved tool names are a frozen read-only view; a caller in the same process cannot free a
// name for an upstream tool.
import test from "node:test";
import assert from "node:assert/strict";
import { RESERVED_TOOL_NAMES } from "../dist/index.js";

test("KI 59: RESERVED_TOOL_NAMES cannot be changed; a mutation attempt throws and the names stay reserved", () => {
  assert.equal(Object.isFrozen(RESERVED_TOOL_NAMES), true);
  for (const method of ["add", "delete", "clear"]) assert.equal(RESERVED_TOOL_NAMES[method], undefined, method);
  assert.throws(() => Set.prototype.delete.call(RESERVED_TOOL_NAMES, "irontrellis_status"), TypeError);
  assert.throws(() => Set.prototype.add.call(RESERVED_TOOL_NAMES, "x"), TypeError);
  assert.throws(() => { RESERVED_TOOL_NAMES.has = () => false; }, TypeError);
  assert.deepEqual([...RESERVED_TOOL_NAMES].sort(), ["irontrellis_status", "irontrellis_why"]);
  assert.equal(RESERVED_TOOL_NAMES.size, 2);
  assert.equal(RESERVED_TOOL_NAMES.has("irontrellis_status"), true);
  assert.equal(RESERVED_TOOL_NAMES.has("other"), false);
});
