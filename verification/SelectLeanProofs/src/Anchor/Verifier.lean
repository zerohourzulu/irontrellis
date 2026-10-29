import Anchor.Types

namespace Anchor

/-- A conflict is scoped to the same pinned history/profile/chain. The predicate
    compares complete statements, so it does not assume digest injectivity. -/
def conflict (a b : Statement) : Bool := decide (
  a.scope = b.scope ∧ a.predecessor = b.predecessor ∧ a ≠ b)

def conflicts (seen : List Statement) (s : Statement) : List Statement :=
  seen.filter (fun old => conflict old s)

def remember (seen : List Statement) (s : Statement) : List Statement :=
  if s ∈ seen then seen else s :: seen

inductive Status where
  | accepted | duplicate | invalid | badBootstrap | badLink | badPrefix | conflict
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

structure Decision where
  status : Status
  anchors : List Submission
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

/-- Diagnostic order is this executable model's explicit order, not a new Core
    refusal precedence. Exact old duplicates never replace the latest head. -/
def accept (scope : Scope) (digest : Statement → Digest) (evidenceOK : EvidenceOK)
    (anchors : List Submission) (x : Submission) : Decision :=
  if anchors.any (fun old => decide (old.statement = x.statement)) then
    ⟨.duplicate, anchors⟩
  else if anchors.any (fun old => conflict old.statement x.statement) then
    ⟨.conflict, anchors⟩
  else if !valid scope evidenceOK x then ⟨.invalid, anchors⟩
  else match anchors with
    | [] => if x.statement.sequence = 0 then ⟨.accepted, [x]⟩
            else ⟨.badBootstrap, []⟩
    | old :: rest =>
      if !link digest old.statement x.statement then ⟨.badLink, old :: rest⟩
      else if !prefixOK old x then ⟨.badPrefix, old :: rest⟩
      else ⟨.accepted, x :: old :: rest⟩

structure State where
  anchors : List Submission := []
  seen : List Statement := []
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

structure Result where
  state : State
  status : Status
  observedConflicts : List Statement
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

/-- Out-of-scope inputs cannot contaminate this scope's observation ledger.
    Conflicts among observed rejected inputs are evidence, not canonical heads. -/
def step (scope : Scope) (digest : Statement → Digest) (evidenceOK : EvidenceOK)
    (state : State) (x : Submission) : Result :=
  let decision := accept scope digest evidenceOK state.anchors x
  let seen := if x.statement.scope = scope then remember state.seen x.statement else state.seen
  let reports := if x.statement.scope = scope then conflicts state.seen x.statement else []
  ⟨⟨decision.anchors, seen⟩, decision.status, reports⟩

def run (scope : Scope) (digest : Statement → Digest) (evidenceOK : EvidenceOK)
    (state : State) (inputs : List Submission) : State :=
  inputs.foldl (fun state x => (step scope digest evidenceOK state x).state) state

end Anchor
