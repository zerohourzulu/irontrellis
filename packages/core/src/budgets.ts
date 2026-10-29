/**
 * Format 2 budgets (SPEC §9), written from the SPEC text: the §9.1 declaration, update and close records, §9.2
 * matching (incl. `roleIds` by the roles the actor currently holds), §9.3 periods, the §9.4 saturating checks
 * (`budgetCheckAfterAllow`, the hook `finalizeCandidate` calls after an ALLOW, SPEC §8.1 step 2), the §9.5 closed-form
 * rollover with `carryBase` (`carryIn`), §9.6 charging and the §9.7 `headroom` view. Everything is pure over
 * `state.budgets`, `state.budgetUsage` and the tenures. (E2 owns this module: review against `lib.mjs` for intent.)
 */
import type { ActionRequest, Amount, DenialCode, ReplayState, U53 } from "./types.ts";

type Rec = Readonly<Record<string, unknown>>;
export type BudgetPeriod = Readonly<{ kind: "NONE" }> | Readonly<{ kind: "FIXED_WINDOW"; lengthMs: U53; originMs: U53; carryUnused: boolean; carryCap: string | null }>;
/** The §7.2 `budget` record (Amounts as strings, as stored). */
export type BudgetRecord = Readonly<{
  budgetId: string; subjects: Readonly<{ actorIds: readonly string[] | null; roleIds: readonly string[] | null; actions: readonly string[] | null; resources: readonly string[] | null }>;
  metric: string | null; period: BudgetPeriod; amountCap: string | null; countCap: U53 | null; perOperationCap: string | null; notBefore: U53 | null; expiresAt: U53 | null;
  status: "ACTIVE" | "CLOSED"; declaredAtPosition: U53; firstPeriod: U53; carryBase: Readonly<{ periodIndex: U53; carryIn: string }> | null; updatedAtPosition: U53 | null; closedAtPosition: U53 | null;
}>;
/** The §7.2 `budgetUsage` record. */
export type BudgetUsageRecord = Readonly<{ budgetId: string; periodIndex: U53; amount: string; count: U53 }>;
/** The first failing budget's code and id (SPEC §9.4), or `null` when every matching budget admits the request. */
export type BudgetVerdict = Readonly<{ code: DenialCode; budgetId: string }>;

/** SPEC §9.3: `0` for NONE; for FIXED_WINDOW `null` before the origin, else `floor((t − originMs) / lengthMs)`. */
export function periodIndex(period: BudgetPeriod, t: U53): U53 | null {
  if (period.kind === "NONE") return 0;
  return t < period.originMs ? null : Math.floor((t - period.originMs) / period.lengthMs);
}
export const usageKey = (budgetId: string, k: U53): string => `${budgetId}/${k}`;

/** The roles `actorId` currently holds (tenures with status CURRENT), SPEC §9.2. */
export function rolesHeldBy(state: ReplayState, actorId: string): ReadonlySet<string> {
  const held = new Set<string>();
  for (const tenureId of state.currentTenureIdsByAgent.get(actorId) ?? []) {
    const tenure = state.tenures.get(tenureId);
    if (tenure !== undefined && !tenure.closed) held.add(tenure.roleId);
  }
  return held;
}
/**
 * A-43.2: whether some request by `actorId` at `t` could match `b` (status, window, actor and role selectors; any
 * action, resource and metric) — the budgets a runtime handle's `headroom` may answer for.
 */
export function budgetConcernsActor(state: ReplayState, b: BudgetRecord, actorId: string, t: U53): boolean {
  if (b.status !== "ACTIVE" || (b.notBefore !== null && t < b.notBefore) || (b.expiresAt !== null && t >= b.expiresAt)) return false;
  if (b.subjects.actorIds !== null && !b.subjects.actorIds.includes(actorId)) return false;
  if (b.subjects.roleIds !== null) { const held = rolesHeldBy(state, actorId); if (!b.subjects.roleIds.some((roleId) => held.has(roleId))) return false; }
  return true;
}
/** SPEC §9.2: whether `request` (metric absent ≡ "amount") evaluated at `t` matches budget `b`. */
export function budgetMatches(state: ReplayState, b: BudgetRecord, request: ActionRequest, t: U53): boolean {
  if (b.status !== "ACTIVE") return false;
  if (b.notBefore !== null && t < b.notBefore) return false;
  if (b.expiresAt !== null && t >= b.expiresAt) return false;
  if (b.subjects.actorIds !== null && !b.subjects.actorIds.includes(request.actorId)) return false;
  if (b.subjects.roleIds !== null) { const held = rolesHeldBy(state, request.actorId); if (!b.subjects.roleIds.some((roleId) => held.has(roleId))) return false; }
  if (b.subjects.actions !== null && !b.subjects.actions.includes(request.action)) return false;
  if (b.subjects.resources !== null && !b.subjects.resources.includes(request.resource)) return false;
  // A-26.1: a `null` metric matches every metric (the budget charges `request.amount` as it stands).
  return b.metric === null || (request.metric ?? "amount") === b.metric;
}
/** The matching budgets of a request in `budgetId` byte order (SPEC §9.4). */
export function matchingBudgets(state: ReplayState, request: ActionRequest, t: U53): readonly BudgetRecord[] {
  const out: BudgetRecord[] = [];
  for (const record of state.budgets.values()) { const b = record as BudgetRecord; if (budgetMatches(state, b, request, t)) out.push(b); }
  return out.sort((x, y) => (Buffer.from(x.budgetId, "utf8").compare(Buffer.from(y.budgetId, "utf8"))));
}

export const MAX_AMOUNT: Amount = (1n << 256n) - 1n;
const minAmount = (a: Amount, b: Amount): Amount => (a < b ? a : b);
const usedAmount = (state: ReplayState, budgetId: string, k: U53): Amount => BigInt(((state.budgetUsage.get(usageKey(budgetId, k)) as BudgetUsageRecord | undefined)?.amount) ?? "0");
/**
 * A-44.1: the rollover index — per budget, the ascending list of periods with usage, derived from the `budgetUsage`
 * records (rebuildable, not a format change), cached per usage map and rebuilt when the map changes size or identity
 * (usage records are only added or updated in place, never removed). `usedPeriods` is then a binary-search slice, so
 * `carryIn` costs O(log n + periods with usage in [p0, k)) instead of a scan of every usage record.
 */
const periodIndexCache = new WeakMap<object, Readonly<{ size: number; byBudget: ReadonlyMap<string, readonly U53[]> }>>();
const usedPeriodsOf = (state: ReplayState, budgetId: string): readonly U53[] => {
  const usage = state.budgetUsage as ReadonlyMap<string, unknown>;
  let cached = periodIndexCache.get(usage);
  if (cached === undefined || cached.size !== usage.size) {
    const byBudget = new Map<string, U53[]>();
    for (const key of usage.keys()) {
      const slash = key.lastIndexOf("/");
      const id = key.slice(0, slash), j = Number(key.slice(slash + 1));
      const list = byBudget.get(id);
      if (list === undefined) byBudget.set(id, [j]); else list.push(j);
    }
    for (const list of byBudget.values()) list.sort((a, b) => a - b);
    cached = Object.freeze({ size: usage.size, byBudget });
    periodIndexCache.set(usage, cached);
  }
  return cached.byBudget.get(budgetId) ?? [];
};
const lowerBound = (list: readonly number[], value: number): number => { let lo = 0, hi = list.length; while (lo < hi) { const mid = (lo + hi) >>> 1; if (list[mid]! < value) lo = mid + 1; else hi = mid; } return lo; };
/** The periods `j` in `[from, to)` that hold usage of `budgetId`, ascending (from the A-44.1 index). */
const usedPeriods = (state: ReplayState, budgetId: string, from: U53, to: U53): readonly U53[] => {
  const list = usedPeriodsOf(state, budgetId);
  return list.slice(lowerBound(list, from), lowerBound(list, to));
};
/**
 * SPEC §9.5 rollover `carryIn(B, k)` as amended by A-50: `f(p0) = c0`, `f(j+1) = min(C, max(0, min(MAX, cap + f(j)) − used(j)))`
 * (the unused part of the saturated effective allowance; intermediate sums are exact bigints), and an
 * idle stretch of `n` periods is `f(j+n) = min(C, f(j) + n·cap)`. The start `(p0, c0)` is `carryBase` when `k` is past
 * it, else `(firstPeriod, 0)`; `carryIn(B, carryBase.periodIndex) = carryBase.carryIn` exactly; `0` for `k ≤ p0`.
 * Work is O(periods with usage between p0 and k), never O(k).
 */
export function carryIn(state: ReplayState, b: BudgetRecord, k: U53): Amount {
  if (b.period.kind === "NONE" || !b.period.carryUnused || b.amountCap === null) return 0n;
  const cap = BigInt(b.amountCap), ccap = BigInt(b.period.carryCap as string);
  let p0 = b.firstPeriod, c0 = 0n;
  if (b.carryBase !== null) {
    if (k === b.carryBase.periodIndex) return BigInt(b.carryBase.carryIn);
    if (k > b.carryBase.periodIndex) { p0 = b.carryBase.periodIndex; c0 = BigInt(b.carryBase.carryIn); }
  }
  if (k <= p0) return 0n;
  let current = p0, carry = c0;
  for (const j of usedPeriods(state, b.budgetId, p0, k)) {
    if (j > current) carry = minAmount(ccap, carry + BigInt(j - current) * cap);
    // A-50: unused EFFECTIVE (saturated) allowance — `max(0, min(MAX, cap + f(j)) − used(j))`.
    let unused = minAmount(MAX_AMOUNT, cap + carry) - usedAmount(state, b.budgetId, j);
    if (unused < 0n) unused = 0n;
    carry = minAmount(ccap, unused);
    current = j + 1;
  }
  if (k > current) carry = minAmount(ccap, carry + BigInt(k - current) * cap);
  return carry;
}
/** SPEC §9.4: `allowed(B, k) = min(MAX, amountCap + carryIn(B, k))`, `remaining = max(0, allowed − used)`; `null` without an amountCap. */
export function remainingAmount(state: ReplayState, b: BudgetRecord, k: U53): Amount | null {
  if (b.amountCap === null) return null;
  const allowed = minAmount(MAX_AMOUNT, BigInt(b.amountCap) + carryIn(state, b, k));
  const remaining = allowed - usedAmount(state, b.budgetId, k);
  return remaining < 0n ? 0n : remaining;
}

/** SPEC §9.1 state of an accepted BUDGET_DECLARED at `position` (`firstPeriod` = periodIndex at max(timestamp, notBefore ?? 0), or 0). */
export function declaredBudgetRecord(effect: Rec, position: U53, timestamp: U53): BudgetRecord {
  const d = effect as Omit<BudgetRecord, "status" | "declaredAtPosition" | "firstPeriod" | "carryBase" | "updatedAtPosition" | "closedAtPosition">;
  return Object.freeze({ ...d, status: "ACTIVE", declaredAtPosition: position, firstPeriod: periodIndex(d.period, Math.max(timestamp, d.notBefore ?? 0)) ?? 0, carryBase: null, updatedAtPosition: null, closedAtPosition: null });
}
/** SPEC §9.1/§9.5 state of an accepted BUDGET_UPDATED: new caps and subjects, `carryBase` frozen under the caps in force before it. */
export function updatedBudgetRecord(state: ReplayState, old: BudgetRecord, effect: Rec, position: U53, timestamp: U53): BudgetRecord {
  const d = effect as Pick<BudgetRecord, "subjects" | "amountCap" | "countCap" | "perOperationCap" | "expiresAt">;
  const k = periodIndex(old.period, timestamp);
  const carryBase = old.period.kind === "FIXED_WINDOW" && old.period.carryUnused && k !== null ? Object.freeze({ periodIndex: k, carryIn: carryIn(state, old, k).toString() }) : null;
  return Object.freeze({ ...old, subjects: d.subjects, amountCap: d.amountCap, countCap: d.countCap, perOperationCap: d.perOperationCap, expiresAt: d.expiresAt, carryBase, updatedAtPosition: position });
}
export function closedBudgetRecord(old: BudgetRecord, position: U53): BudgetRecord {
  return Object.freeze({ ...old, status: "CLOSED", closedAtPosition: position });
}
/** SPEC §9.6: the `budgetUsage` records an admission charges (every matching budget's current period: count + 1, amount + a). */
export function chargedUsage(state: ReplayState, request: ActionRequest, t: U53): readonly BudgetUsageRecord[] {
  const amount = request.amount ?? 0n;
  const out: BudgetUsageRecord[] = [];
  for (const b of matchingBudgets(state, request, t)) {
    const k = periodIndex(b.period, t);
    if (k === null) continue;
    const current = state.budgetUsage.get(usageKey(b.budgetId, k)) as BudgetUsageRecord | undefined;
    out.push(Object.freeze({ budgetId: b.budgetId, periodIndex: k, amount: (BigInt(current?.amount ?? "0") + amount).toString(), count: (current?.count ?? 0) + 1 }));
  }
  return out;
}

export const MAX_MATCHING_BUDGETS = 16;
/**
 * SPEC §9.4 over the pre-event state at `evaluationTime`: `null` (pass) or `{code, budgetId}`. Called from
 * `finalizeCandidate` (every `authorize`, and so every admission re-derivation and every CORE/BUDGET refusal
 * re-derivation). The request's amount is the engine bigint (0 when absent) and its metric defaults to `"amount"`.
 * Order: BUDGET_SET_TOO_LARGE above 16 matching budgets (budgetId = the 17th), then per budget in byte order:
 * PERIOD_UNDEFINED, PER_OPERATION_EXCEEDED, COUNT_EXCEEDED, AMOUNT_EXCEEDED, AMOUNT_OVERFLOW (SPEC §3.3 closure).
 */
export function budgetCheckAfterAllow(state: ReplayState, request: ActionRequest, evaluationTime: U53): BudgetVerdict | null {
  const matching = matchingBudgets(state, request, evaluationTime);
  if (matching.length > MAX_MATCHING_BUDGETS) return { code: "BUDGET_SET_TOO_LARGE", budgetId: matching[MAX_MATCHING_BUDGETS]!.budgetId };
  const amount = request.amount ?? 0n;
  for (const b of matching) {
    const k = periodIndex(b.period, evaluationTime);
    if (k === null) return { code: "BUDGET_PERIOD_UNDEFINED", budgetId: b.budgetId };
    const used = state.budgetUsage.get(usageKey(b.budgetId, k)) as BudgetUsageRecord | undefined;
    if (b.perOperationCap !== null && amount > BigInt(b.perOperationCap)) return { code: "BUDGET_PER_OPERATION_EXCEEDED", budgetId: b.budgetId };
    if (b.countCap !== null && (used?.count ?? 0) + 1 > b.countCap) return { code: "BUDGET_COUNT_EXCEEDED", budgetId: b.budgetId };
    if (b.amountCap !== null && amount > (remainingAmount(state, b, k) as Amount)) return { code: "BUDGET_AMOUNT_EXCEEDED", budgetId: b.budgetId };
    if (BigInt(used?.amount ?? "0") + amount > MAX_AMOUNT) return { code: "AMOUNT_OVERFLOW", budgetId: b.budgetId };
  }
  return null;
}
/**
 * SPEC §9.7 headroom (pure view): `null` for an unknown budget. `at` is any U53; a view of the past is computed as-of
 * that time over the current record set. Adapter op `headroom`.
 */
export function headroom(state: ReplayState, budgetId: string, at: U53): Readonly<Record<string, unknown>> | null {
  const b = state.budgets.get(budgetId) as BudgetRecord | undefined;
  if (b === undefined) return null;
  const k = periodIndex(b.period, at);
  const active = b.status === "ACTIVE" && (b.notBefore === null || at >= b.notBefore) && (b.expiresAt === null || at < b.expiresAt) && k !== null;
  const used = k === null ? undefined : state.budgetUsage.get(usageKey(b.budgetId, k)) as BudgetUsageRecord | undefined;
  const carry = k === null ? 0n : carryIn(state, b, k);
  const remaining = b.amountCap === null ? null : (k === null ? BigInt(b.amountCap) : (remainingAmount(state, b, k) as Amount)).toString();
  return Object.freeze({
    budgetId, active, periodIndex: k, usedAmount: used?.amount ?? "0", usedCount: used?.count ?? 0, carryIn: carry.toString(), remainingAmount: remaining,
    remainingCount: b.countCap === null ? null : Math.max(0, b.countCap - (used?.count ?? 0)),
  });
}
