import Std

/-!
Corrected-scope OPTIONAL PILOT: parent closure and aggregate capped accounting.
This is not an implementation refinement or a complete admission authorizer.
Resolved main/intersection parent paths are inputs. Canonical parent links,
presence, path length and duplicate IDs are checked; grantor/root recognition,
attenuation, intersection eligibility, prohibitions and all signatures are NOT.
Nat IDs abstract exact identifiers; one immutable Registry assigns each ID its
parent and caps, so two copies cannot carry different parents or caps.
The total initial ledger explicitly supplies every ID's usage. It is NOT a
default-to-zero lookup for missing capped-usage records. A production adapter
must reject missing capped usage before constructing this input.
Only legacy per-capped-dimension authorityUsage is modeled. Format-2 all-usage
counters, budgets, mutable caps, migration, storage and external effects are not.
Arithmetic is exact Nat, with explicit U256 amount/U53 count guards. Initial
safe-state assumptions are explicit. Charges are serialized; pure evaluation
does not charge. Accepted-history conservation includes the initial ledger.
-/

namespace Accounting

def maxAmount : Nat := 2 ^ 256 - 1
def maxCount : Nat := 2 ^ 53 - 1

inductive Node where
  | root (identifier : Nat)
  | child (identifier : Nat) (parent : Node)
  deriving Repr, DecidableEq

def Node.id : Node → Nat
  | .root i => i
  | .child i _ => i

/-- Traverses actual parent constructors, rather than taking supplied charge IDs. -/
def Node.ids : Node → List Nat
  | .root i => [i]
  | .child i parent => i :: parent.ids

inductive Ancestor : Node → Node → Prop where
  | self (n : Node) : Ancestor n n
  | climb {a p : Node} (h : Ancestor a p) (i : Nat) : Ancestor a (.child i p)

theorem own_id_mem (n : Node) : n.id ∈ n.ids := by
  cases n <;> simp [Node.id, Node.ids]

theorem ancestor_id_mem {a n : Node} (h : Ancestor a n) : a.id ∈ n.ids := by
  induction h with
  | self => exact own_id_mem a
  | climb h i ih => simp [Node.ids, ih]

def unique : List Nat → List Nat
  | [] => []
  | x :: xs => if x ∈ unique xs then unique xs else x :: unique xs

theorem mem_unique (x : Nat) (xs : List Nat) : x ∈ unique xs ↔ x ∈ xs := by
  induction xs with
  | nil => simp [unique]
  | cons a rest ih =>
      by_cases ha : a ∈ unique rest
      · simp only [unique, if_pos ha, List.mem_cons]
        constructor
        · intro hx; exact Or.inr (ih.mp hx)
        · intro hx
          rcases hx with rfl | hx
          · exact ha
          · exact ih.mpr hx
      · simpa [unique, ha] using (or_congr Iff.rfl ih)

theorem unique_nodup (xs : List Nat) : (unique xs).Nodup := by
  induction xs with
  | nil => simp [unique]
  | cons x xs ih =>
      by_cases hx : x ∈ unique xs <;> simp [unique, hx, ih]

structure Proposal where
  paths : List Node
  amount : Option Nat
  deriving Repr, DecidableEq

def controllers (p : Proposal) : List Nat := unique (p.paths.flatMap Node.ids)

theorem controllers_nodup (p : Proposal) : (controllers p).Nodup :=
  unique_nodup _

theorem ancestor_in_controllers {a n : Node} {p : Proposal}
    (selected : n ∈ p.paths) (h : Ancestor a n) : a.id ∈ controllers p := by
  apply (mem_unique _ _).mpr
  exact List.mem_flatMap.mpr ⟨n, selected, ancestor_id_mem h⟩

structure Caps where
  quantitative : Bool := false
  maxCumulativeAmount : Option Nat := none
  maxTransactions : Option Nat := none
  deriving Repr, DecidableEq

def capsCheck (c : Caps) : Bool :=
  (match c.maxCumulativeAmount with
    | none => true
    | some cap => decide (cap ≤ maxAmount) && c.quantitative) &&
  (match c.maxTransactions with
    | none => true
    | some cap => decide (cap ≤ maxCount))

/-- Global ID-to-parent/cap identity, fixed throughout the run. -/
structure Registry where
  present : List Nat
  parent : Nat → Option Nat
  caps : Nat → Caps

def coherent (r : Registry) : Node → Bool
  | .root i => decide (i ∈ r.present ∧ r.parent i = none)
  | .child i parent => decide (i ∈ r.present ∧ r.parent i = some parent.id) &&
      coherent r parent

def shapeCheck (r : Registry) (p : Proposal) : Bool :=
  decide (p.paths ≠ []) && p.paths.all (fun n => coherent r n &&
    decide (n.ids.length ≤ 32) && decide n.ids.Nodup) &&
    decide ((controllers p).length ≤ 256) &&
    (controllers p).all (fun i => capsCheck (r.caps i))

structure Usage where
  cumulative : Nat
  count : Nat
  deriving Repr, DecidableEq

abbrev Ledger := Nat → Usage

def amountDelta (c : Caps) (amount : Option Nat) : Nat :=
  if c.maxCumulativeAmount.isSome then amount.getD 0 else 0

def countDelta (c : Caps) : Nat := if c.maxTransactions.isSome then 1 else 0

def bump (c : Caps) (u : Usage) (amount : Option Nat) : Usage :=
  ⟨u.cumulative + amountDelta c amount, u.count + countDelta c⟩

def Bound : Option Nat → Nat → Prop
  | none, _ => True
  | some b, value => value ≤ b

instance (b : Option Nat) (v : Nat) : Decidable (Bound b v) := by
  cases b <;> unfold Bound <;> infer_instance

def AmountValid : Option Nat → Prop
  | none => True
  | some a => a ≤ maxAmount

instance (a : Option Nat) : Decidable (AmountValid a) := by
  cases a <;> unfold AmountValid <;> infer_instance

def CumulativePass (c : Caps) (u : Usage) (amount : Option Nat) : Prop :=
  match c.maxCumulativeAmount with
  | none => True
  | some cap => match amount with
    | none => False
    | some a => u.cumulative + a ≤ cap ∧ u.cumulative + a ≤ maxAmount

def CountPass (c : Caps) (u : Usage) : Prop :=
  match c.maxTransactions with
  | none => True
  | some cap => u.count + 1 ≤ cap ∧ u.count + 1 ≤ maxCount

instance (c : Caps) (u : Usage) (a : Option Nat) : Decidable (CumulativePass c u a) := by
  unfold CumulativePass
  cases c.maxCumulativeAmount <;> cases a <;> infer_instance

instance (c : Caps) (u : Usage) : Decidable (CountPass c u) := by
  unfold CountPass
  cases c.maxTransactions <;> infer_instance

def PerAuthorityPass (c : Caps) (u : Usage) (amount : Option Nat) : Prop :=
  AmountValid amount ∧ (c.quantitative = true → amount.isSome = true) ∧
    CumulativePass c u amount ∧ CountPass c u

instance (c : Caps) (u : Usage) (a : Option Nat) : Decidable (PerAuthorityPass c u a) := by
  unfold PerAuthorityPass
  infer_instance

def canCharge (r : Registry) (u : Ledger) (p : Proposal) : Bool :=
  shapeCheck r p && (controllers p).all (fun i => decide (PerAuthorityPass (r.caps i) (u i) p.amount))

/-- Simultaneous per-ID update charges each included authority once, even when
    it is an ancestor of several selected paths. -/
def debit (r : Registry) (u : Ledger) (p : Proposal) : Ledger :=
  fun i => if i ∈ controllers p then bump (r.caps i) (u i) p.amount else u i

theorem passed_for_controller {r : Registry} {u : Ledger} {p : Proposal}
    (pass : canCharge r u p = true) {i : Nat} (member : i ∈ controllers p) :
    PerAuthorityPass (r.caps i) (u i) p.amount := by
  simp only [canCharge, Bool.and_eq_true, List.all_eq_true, decide_eq_true_eq] at pass
  exact pass.2 i member

theorem ancestor_charged_once {r : Registry} {u : Ledger} {p : Proposal} {a n : Node}
    (selected : n ∈ p.paths) (h : Ancestor a n) :
    debit r u p a.id = bump (r.caps a.id) (u a.id) p.amount := by
  simp [debit, ancestor_in_controllers selected h]

theorem ancestor_guarded {r : Registry} {u : Ledger} {p : Proposal} {a n : Node}
    (pass : canCharge r u p = true) (selected : n ∈ p.paths) (h : Ancestor a n) :
    PerAuthorityPass (r.caps a.id) (u a.id) p.amount :=
  passed_for_controller pass (ancestor_in_controllers selected h)

def SafeUsage (c : Caps) (u : Usage) : Prop :=
  Bound c.maxCumulativeAmount u.cumulative ∧ Bound c.maxTransactions u.count ∧
    u.cumulative ≤ maxAmount ∧ u.count ≤ maxCount

def Safe (r : Registry) (u : Ledger) : Prop := ∀ i, SafeUsage (r.caps i) (u i)

theorem bump_safe {c : Caps} {u : Usage} {a : Option Nat}
    (before : SafeUsage c u) (pass : PerAuthorityPass c u a) :
    SafeUsage c (bump c u a) := by
  rcases c with ⟨q, cum, count⟩
  cases cum <;> cases count <;> cases a <;>
    simp_all [SafeUsage, PerAuthorityPass, CumulativePass, CountPass, bump,
      amountDelta, countDelta, Bound]

theorem debit_safe {r : Registry} {u : Ledger} {p : Proposal}
    (before : Safe r u) (pass : canCharge r u p = true) : Safe r (debit r u p) := by
  intro i
  by_cases hi : i ∈ controllers p
  · simpa [debit, hi] using bump_safe (before i) (passed_for_controller pass hi)
  · simpa [debit, hi] using before i

structure State where
  usage : Ledger
  accepted : List Proposal

def step (r : Registry) (s : State) (p : Proposal) : State :=
  if canCharge r s.usage p then ⟨debit r s.usage p, p :: s.accepted⟩ else s

def run (r : Registry) (initial : State) (attempts : List Proposal) : State :=
  attempts.foldl (step r) initial

theorem rejected_unchanged {r : Registry} {s : State} {p : Proposal}
    (rejected : canCharge r s.usage p = false) : step r s p = s := by
  simp [step, rejected]

theorem step_safe {r : Registry} {s : State} {p : Proposal}
    (before : Safe r s.usage) : Safe r (step r s p).usage := by
  by_cases pass : canCharge r s.usage p = true
  · simpa [step, pass] using debit_safe before pass
  · simpa [step, pass] using before

theorem run_safe {r : Registry} {s : State} (attempts : List Proposal)
    (before : Safe r s.usage) : Safe r (run r s attempts).usage := by
  induction attempts generalizing s with
  | nil => exact before
  | cons p ps ih => exact ih (step_safe before)

def amountCharge (r : Registry) (i : Nat) (p : Proposal) : Nat :=
  if i ∈ controllers p then amountDelta (r.caps i) p.amount else 0

def countCharge (r : Registry) (i : Nat) (p : Proposal) : Nat :=
  if i ∈ controllers p then countDelta (r.caps i) else 0

def Conserved (r : Registry) (baseline : Ledger) (s : State) : Prop := ∀ i,
  (s.usage i).cumulative = (baseline i).cumulative + (s.accepted.map (amountCharge r i)).sum ∧
  (s.usage i).count = (baseline i).count + (s.accepted.map (countCharge r i)).sum

theorem debit_amount {r : Registry} {u : Ledger} {p : Proposal} (i : Nat) :
    (debit r u p i).cumulative = (u i).cumulative + amountCharge r i p := by
  by_cases hi : i ∈ controllers p <;> simp [debit, amountCharge, hi, bump]

theorem debit_count {r : Registry} {u : Ledger} {p : Proposal} (i : Nat) :
    (debit r u p i).count = (u i).count + countCharge r i p := by
  by_cases hi : i ∈ controllers p <;> simp [debit, countCharge, hi, bump]

theorem step_conserved {r : Registry} {baseline : Ledger} {s : State} {p : Proposal}
    (before : Conserved r baseline s) : Conserved r baseline (step r s p) := by
  by_cases pass : canCharge r s.usage p = true
  · intro i
    have prev := before i
    simp only [step, pass, Bool.true_eq, ↓reduceIte, List.map_cons, List.sum_cons]
    rw [debit_amount, debit_count]
    omega
  · simpa [step, pass] using before

theorem run_conserved {r : Registry} {baseline : Ledger} {s : State}
    (attempts : List Proposal) (before : Conserved r baseline s) :
    Conserved r baseline (run r s attempts) := by
  induction attempts generalizing s with
  | nil => exact before
  | cons p ps ih => exact ih (step_conserved before)

theorem initialized_conserved (r : Registry) (baseline : Ledger) :
    Conserved r baseline ⟨baseline, []⟩ := by
  intro i
  simp [Conserved]

/-- Main accounting theorem: arbitrary initial safe ledger plus the exact sum
    of accepted suffix charges, and preservation of caps/U256/U53 bounds. -/
theorem aggregate_accounting (r : Registry) (baseline : Ledger) (attempts : List Proposal)
    (initialSafe : Safe r baseline) :
    Conserved r baseline (run r ⟨baseline, []⟩ attempts) ∧
    Safe r (run r ⟨baseline, []⟩ attempts).usage := by
  exact ⟨run_conserved attempts (initialized_conserved r baseline), run_safe attempts initialSafe⟩

theorem cumulative_sum_bound (r : Registry) (baseline : Ledger) (attempts : List Proposal)
    (initialSafe : Safe r baseline) (i cap : Nat)
    (capped : (r.caps i).maxCumulativeAmount = some cap) :
    (baseline i).cumulative +
      ((run r ⟨baseline, []⟩ attempts).accepted.map (amountCharge r i)).sum ≤ cap := by
  have facts := aggregate_accounting r baseline attempts initialSafe
  have bound := (facts.2 i).1
  rw [capped] at bound
  change ((run r ⟨baseline, []⟩ attempts).usage i).cumulative ≤ cap at bound
  rw [(facts.1 i).1] at bound
  exact bound

theorem count_sum_bound (r : Registry) (baseline : Ledger) (attempts : List Proposal)
    (initialSafe : Safe r baseline) (i cap : Nat)
    (capped : (r.caps i).maxTransactions = some cap) :
    (baseline i).count +
      ((run r ⟨baseline, []⟩ attempts).accepted.map (countCharge r i)).sum ≤ cap := by
  have facts := aggregate_accounting r baseline attempts initialSafe
  have bound := (facts.2 i).2.1
  rw [capped] at bound
  change ((run r ⟨baseline, []⟩ attempts).usage i).count ≤ cap at bound
  rw [(facts.1 i).2] at bound
  exact bound

theorem ancestor_amount_term {r : Registry} {p : Proposal} {a n : Node}
    (selected : n ∈ p.paths) (h : Ancestor a n) :
    amountCharge r a.id p = amountDelta (r.caps a.id) p.amount := by
  simp [amountCharge, ancestor_in_controllers selected h]

theorem ancestor_count_term {r : Registry} {p : Proposal} {a n : Node}
    (selected : n ∈ p.paths) (h : Ancestor a n) :
    countCharge r a.id p = countDelta (r.caps a.id) := by
  simp [countCharge, ancestor_in_controllers selected h]

#print axioms own_id_mem
#print axioms ancestor_id_mem
#print axioms mem_unique
#print axioms unique_nodup
#print axioms controllers_nodup
#print axioms ancestor_in_controllers
#print axioms passed_for_controller
#print axioms ancestor_charged_once
#print axioms ancestor_guarded
#print axioms bump_safe
#print axioms debit_safe
#print axioms rejected_unchanged
#print axioms step_safe
#print axioms run_safe
#print axioms debit_amount
#print axioms debit_count
#print axioms step_conserved
#print axioms run_conserved
#print axioms initialized_conserved
#print axioms aggregate_accounting
#print axioms cumulative_sum_bound
#print axioms count_sum_bound
#print axioms ancestor_amount_term
#print axioms ancestor_count_term

end Accounting
