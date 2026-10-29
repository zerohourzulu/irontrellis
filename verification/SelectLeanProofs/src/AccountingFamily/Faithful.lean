import AccountingFamily.Accounting

/-! Native capped-authority model. Registry/caps immutable; eligibility mutable.
Required partners are computed from main-path requirements and closed through the
registry. Both ledgers remain after revocation. `otherChecks` explicitly attests
checks outside this slice. No budgets or implementation refinement theorem. -/
namespace Faithful
open Accounting
structure Registry where
  base : Accounting.Registry
  required : Nat → List Nat
  independent : Nat → Bool
  grantee : Nat → Nat
  recognized : Nat → Bool

def resolve (r : Registry) : Nat → Nat → Option Node
  | 0, _ => none
  | fuel + 1, i => if i ∈ r.base.present then
      match r.base.parent i with
      | none => some (.root i)
      | some parent => (resolve r fuel parent).map (Node.child i)
    else none

def pathRequired (r : Registry) (n : Node) : List Nat := unique (n.ids.flatMap r.required)
def closeRequired (r : Registry) : Nat → List Nat → List Nat → Option (List Nat)
  | 0, _, _ => none
  | _ + 1, [], seen => some seen
  | fuel + 1, i :: pending, seen =>
      if i ∈ seen then closeRequired r fuel pending seen
      else match resolve r 32 i with
        | none => none
        | some n => closeRequired r fuel (pending ++ pathRequired r n) (i :: seen)
structure Proposal where
  main : Node
  partners : List Node
  amount : Option Nat
  actor : Nat
  otherChecks : Bool
  deriving Repr, DecidableEq

def accountingProposal (p : Proposal) : Accounting.Proposal := ⟨p.main :: p.partners, p.amount⟩
def controllers (p : Proposal) : List Nat := Accounting.controllers (accountingProposal p)
def partnerIds (p : Proposal) : List Nat := p.partners.map Node.id

def requirementsComplete (r : Registry) (p : Proposal) : Bool :=
  (pathRequired r p.main).all (fun i => i ∈ partnerIds p) &&
  p.partners.all (fun n => (pathRequired r n).all (fun i => i ∈ partnerIds p)) &&
  match closeRequired r (1 + (r.base.present.length + 1) * 1024) (pathRequired r p.main) [] with
  | none => false
  | some needed => needed.all (fun i => i ∈ partnerIds p) && (partnerIds p).all (fun i => i ∈ needed)

def pathRecognized (r : Registry) (n : Node) : Bool := r.recognized (n.ids.getLast!)
def graphCheck (r : Registry) (p : Proposal) : Bool :=
  p.otherChecks && requirementsComplete r p && decide (partnerIds p).Nodup &&
  p.main.ids.all r.independent && pathRecognized r p.main &&
  decide (r.grantee p.main.id = p.actor) &&
  p.partners.all (fun n => !(n.ids.all r.independent) && pathRecognized r n && decide (r.grantee n.id = p.actor))
structure Entry where
  legacy : Ledger
  allUsage : Ledger
  legacyPresent : Nat → Bool
  allPresent : Nat → Bool
  eligible : Nat → Bool

def allBump (u : Usage) (a : Option Nat) : Usage := ⟨u.cumulative + a.getD 0, u.count + 1⟩
def allDebit (s : Entry) (p : Proposal) : Ledger :=
  fun i => if i ∈ controllers p then allBump (s.allUsage i) p.amount else s.allUsage i

def capped (c : Caps) : Bool := c.maxCumulativeAmount.isSome || c.maxTransactions.isSome

def admissionCheck (r : Registry) (s : Entry) (p : Proposal) : Bool :=
  graphCheck r p && canCharge r.base s.legacy (accountingProposal p) &&
  (controllers p).all (fun i => s.eligible i && (!capped (r.base.caps i) || s.legacyPresent i) &&
    decide ((s.allUsage i).cumulative + p.amount.getD 0 ≤ maxAmount) &&
    decide ((s.allUsage i).count + 1 ≤ maxCount))
structure Charge where
  proposal : Proposal
  deriving Repr, DecidableEq
structure State where
  entry : Entry
  accepted : List Charge

def chargedEntry (r : Registry) (s : Entry) (p : Proposal) : Entry :=
  { s with legacy := debit r.base s.legacy (accountingProposal p)
           allUsage := allDebit s p
           allPresent := fun i => if i ∈ controllers p then true else s.allPresent i }
def admit (r : Registry) (s : State) (p : Proposal) : State :=
  if admissionCheck r s.entry p then ⟨chargedEntry r s.entry p, ⟨p⟩ :: s.accepted⟩ else s

def revoke (s : State) (i : Nat) : State :=
  { s with entry := { s.entry with eligible := fun j => if j = i then false else s.entry.eligible j } }
inductive Event where
  | admission (p : Proposal)
  | revocation (i : Nat)
  deriving Repr, DecidableEq

def step (r : Registry) (s : State) : Event → State
  | .admission p => admit r s p
  | .revocation i => revoke s i

def run (r : Registry) (s : State) (es : List Event) : State := es.foldl (step r) s

theorem controller_union_nodup (p : Proposal) : (controllers p).Nodup := Accounting.controllers_nodup _
theorem main_ancestor_in_controller {a : Node} {p : Proposal} (h : Ancestor a p.main) :
    a.id ∈ controllers p := ancestor_in_controllers (by simp [accountingProposal]) h

theorem partner_ancestor_in_controller {a n : Node} {p : Proposal}
    (selected : n ∈ p.partners) (h : Ancestor a n) : a.id ∈ controllers p :=
  ancestor_in_controllers (by simp [accountingProposal, selected]) h

theorem required_main_partner_present {r : Registry} {p : Proposal}
    (h : requirementsComplete r p = true) {i : Nat}
    (required : i ∈ pathRequired r p.main) : i ∈ partnerIds p := by
  simp only [requirementsComplete, Bool.and_eq_true] at h
  exact of_decide_eq_true ((List.all_eq_true.mp h.1.1) i required)

theorem accepted_graph {r : Registry} {s : Entry} {p : Proposal}
    (h : admissionCheck r s p = true) : graphCheck r p = true := by
  simp only [admissionCheck, Bool.and_eq_true] at h
  exact h.1.1

theorem graph_requirements {r : Registry} {p : Proposal}
    (h : graphCheck r p = true) : requirementsComplete r p = true := by
  simp only [graphCheck, Bool.and_eq_true] at h
  exact h.1.1.1.1.1.2

theorem omitted_required_main_partner_rejected {r : Registry} {s : Entry} {p : Proposal}
    {i : Nat} (required : i ∈ pathRequired r p.main) (omitted : i ∉ partnerIds p) :
    admissionCheck r s p = false := by
  cases h : admissionCheck r s p with
  | false => rfl
  | true => exact False.elim (omitted (required_main_partner_present (graph_requirements (accepted_graph h)) required))

theorem accepted_accounting_check {r : Registry} {s : Entry} {p : Proposal}
    (h : admissionCheck r s p = true) : canCharge r.base s.legacy (accountingProposal p) = true := by
  simp only [admissionCheck, Bool.and_eq_true] at h
  exact h.1.2

theorem accepted_controller_eligible {r : Registry} {s : Entry} {p : Proposal}
    (h : admissionCheck r s p = true) {i : Nat} (hi : i ∈ controllers p) : s.eligible i = true := by
  simp only [admissionCheck, Bool.and_eq_true] at h
  have row := List.all_eq_true.mp h.2 i hi
  simp only [Bool.and_eq_true] at row
  exact row.1.1.1

theorem accepted_capped_usage_present {r : Registry} {s : Entry} {p : Proposal}
    (h : admissionCheck r s p = true) {i : Nat} (hi : i ∈ controllers p)
    (hc : capped (r.base.caps i) = true) : s.legacyPresent i = true := by
  simp only [admissionCheck, Bool.and_eq_true] at h
  have row := List.all_eq_true.mp h.2 i hi
  simp only [Bool.and_eq_true] at row
  simpa [hc] using row.1.1.2

theorem rejected_unchanged_in_model {r : Registry} {s : State} {p : Proposal}
    (h : admissionCheck r s.entry p = false) : admit r s p = s := by simp [admit, h]

theorem accepted_main_ancestor_once {r : Registry} {s : Entry} {p : Proposal} {a : Node}
    (h : Ancestor a p.main) :
    (chargedEntry r s p).legacy a.id = bump (r.base.caps a.id) (s.legacy a.id) p.amount := by
  exact ancestor_charged_once (by simp [accountingProposal]) h

theorem all_controller_once {s : Entry} {p : Proposal} {i : Nat} (hi : i ∈ controllers p) :
    allDebit s p i = allBump (s.allUsage i) p.amount := by simp [allDebit, hi]

theorem revoked_retains_legacy (s : State) (i : Nat) : (revoke s i).entry.legacy = s.entry.legacy := rfl

theorem revoked_retains_all_usage (s : State) (i : Nat) : (revoke s i).entry.allUsage = s.entry.allUsage := rfl

theorem revoked_ineligible (s : State) (i : Nat) : (revoke s i).entry.eligible i = false := by simp [revoke]

theorem revoked_controller_rejected {r : Registry} {s : State} {p : Proposal} {i : Nat}
    (hi : i ∈ controllers p) : admissionCheck r (revoke s i).entry p = false := by
  cases h : admissionCheck r (revoke s i).entry p with
  | false => rfl
  | true =>
    have bad := accepted_controller_eligible h hi
    simp [revoke] at bad

def amountCharge (r : Registry) (i : Nat) (c : Charge) : Nat := Accounting.amountCharge r.base i (accountingProposal c.proposal)
def countCharge (r : Registry) (i : Nat) (c : Charge) : Nat := Accounting.countCharge r.base i (accountingProposal c.proposal)
def allAmountCharge (i : Nat) (c : Charge) : Nat := if i ∈ controllers c.proposal then c.proposal.amount.getD 0 else 0
def allCountCharge (i : Nat) (c : Charge) : Nat := if i ∈ controllers c.proposal then 1 else 0

def Conserved (r : Registry) (legacy all : Ledger) (s : State) : Prop := ∀ i,
  (s.entry.legacy i).cumulative = (legacy i).cumulative + (s.accepted.map (amountCharge r i)).sum ∧
  (s.entry.legacy i).count = (legacy i).count + (s.accepted.map (countCharge r i)).sum ∧
  (s.entry.allUsage i).cumulative = (all i).cumulative + (s.accepted.map (allAmountCharge i)).sum ∧
  (s.entry.allUsage i).count = (all i).count + (s.accepted.map (allCountCharge i)).sum

theorem all_debit_amount (s : Entry) (p : Proposal) (i : Nat) :
    (allDebit s p i).cumulative = (s.allUsage i).cumulative + allAmountCharge i ⟨p⟩ := by
  by_cases hi : i ∈ controllers p <;> simp [allDebit, allAmountCharge, allBump, hi]

theorem all_debit_count (s : Entry) (p : Proposal) (i : Nat) :
    (allDebit s p i).count = (s.allUsage i).count + allCountCharge i ⟨p⟩ := by
  by_cases hi : i ∈ controllers p <;> simp [allDebit, allCountCharge, allBump, hi]

theorem admit_conserved {r : Registry} {legacy all : Ledger} {s : State} {p : Proposal}
    (h : Conserved r legacy all s) : Conserved r legacy all (admit r s p) := by
  by_cases hp : admissionCheck r s.entry p = true
  · intro i
    have prev := h i
    simp only [admit, hp, Bool.true_eq, ↓reduceIte, chargedEntry, List.map_cons, List.sum_cons]
    rw [debit_amount, debit_count, all_debit_amount, all_debit_count]
    simp only [amountCharge, countCharge] at *
    omega
  · simpa [admit, hp] using h

theorem step_conserved {r : Registry} {legacy all : Ledger} {s : State} (e : Event)
    (h : Conserved r legacy all s) : Conserved r legacy all (step r s e) := by
  cases e with
  | admission p => exact admit_conserved h
  | revocation i => exact h

theorem run_conserved {r : Registry} {legacy all : Ledger} {s : State} (es : List Event)
    (h : Conserved r legacy all s) : Conserved r legacy all (run r s es) := by
  induction es generalizing s with
  | nil => exact h
  | cons e es ih => exact ih (step_conserved e h)

theorem legacy_step_safe {r : Registry} {s : State} (e : Event)
    (h : Safe r.base s.entry.legacy) : Safe r.base (step r s e).entry.legacy := by
  cases e with
  | revocation i => exact h
  | admission p =>
    by_cases hp : admissionCheck r s.entry p = true
    · simpa [step, admit, hp, chargedEntry] using debit_safe h (accepted_accounting_check hp)
    · simpa [step, admit, hp] using h

theorem legacy_run_safe {r : Registry} {s : State} (es : List Event)
    (h : Safe r.base s.entry.legacy) : Safe r.base (run r s es).entry.legacy := by
  induction es generalizing s with
  | nil => exact h
  | cons e es ih => exact ih (legacy_step_safe e h)

def rebuildLegacy (r : Registry) (baseline : Ledger) (records : List Charge) : Ledger := fun i =>
  ⟨(baseline i).cumulative + (records.map (amountCharge r i)).sum,
   (baseline i).count + (records.map (countCharge r i)).sum⟩
def rebuildAll (baseline : Ledger) (records : List Charge) : Ledger := fun i =>
  ⟨(baseline i).cumulative + (records.map (allAmountCharge i)).sum,
   (baseline i).count + (records.map (allCountCharge i)).sum⟩

theorem usage_ext {a b : Usage} (ha : a.cumulative = b.cumulative) (hc : a.count = b.count) : a = b := by
  cases a; cases b; simp_all

theorem rebuild_legacy_eq {r : Registry} {legacy all : Ledger} {s : State}
    (h : Conserved r legacy all s) : rebuildLegacy r legacy s.accepted = s.entry.legacy := by
  funext i
  exact usage_ext (h i).1.symm (h i).2.1.symm

theorem rebuild_all_eq {r : Registry} {legacy all : Ledger} {s : State}
    (h : Conserved r legacy all s) : rebuildAll all s.accepted = s.entry.allUsage := by
  funext i
  exact usage_ext (h i).2.2.1.symm (h i).2.2.2.symm

theorem initialized_conserved (r : Registry) (entry : Entry) : Conserved r entry.legacy entry.allUsage ⟨entry, []⟩ := by
  intro i
  simp [Conserved]

theorem aggregate_with_revocations (r : Registry) (entry : Entry) (es : List Event)
    (safe : Safe r.base entry.legacy) :
    Conserved r entry.legacy entry.allUsage (run r ⟨entry, []⟩ es) ∧
    Safe r.base (run r ⟨entry, []⟩ es).entry.legacy ∧
    rebuildLegacy r entry.legacy (run r ⟨entry, []⟩ es).accepted = (run r ⟨entry, []⟩ es).entry.legacy ∧
    rebuildAll entry.allUsage (run r ⟨entry, []⟩ es).accepted = (run r ⟨entry, []⟩ es).entry.allUsage := by
  have conserved := run_conserved es (initialized_conserved r entry)
  exact ⟨conserved, legacy_run_safe es safe, rebuild_legacy_eq conserved, rebuild_all_eq conserved⟩
end Faithful
