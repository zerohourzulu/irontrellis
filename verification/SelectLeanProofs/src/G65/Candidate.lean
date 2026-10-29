import Termination.TerminationNonExpansion
import Termination.TerminationWitnesses

/- Post-N1 G6.5 A-135 slice, written after exact text arrived. This new module
   reuses frozen types and path/prohibition algebra, adds the explicit candidate
   amount set and rank, and keeps the format-2 all-controller ledger distinct
   from corpus.usage (the legacy capped ledger). It is not a replacement claim
   for the whole raw decoder, replay, budget or cryptographic implementation. -/
namespace Authority.G65
open Authority.G64

def failureSets (format2Usage : List Usage) (c : Corpus) (g : Graph) (r : Request) (t : Nat) : List (Code × List Id) :=
  let selectedIds (pred : Permission → Bool) := (g.grants.filter pred).map (·.authorityId)
  [(.REVOKED, selectedIds (fun p => c.revoked.contains p.authorityId)),
   (.NOT_YET_VALID, selectedIds (fun p => p.constraints.notBefore.any (t < ·))),
   (.EXPIRED, selectedIds (fun p => p.constraints.expiresAt.any (t >= ·))),
   (.MISSING_INTERSECTION, g.missing),
   (.ACTION_NOT_ALLOWED, selectedIds (fun p => !p.constraints.actions.contains r.action)),
   (.RESOURCE_NOT_ALLOWED, selectedIds (fun p => !p.constraints.resources.contains r.resource)),
   (.AMOUNT_REQUIRED, selectedIds (fun p => p.constraints.quantitative && r.amount.isNone)),
   (.AMOUNT_EXCEEDED, selectedIds (fun p => p.constraints.maxAmount.any (fun cap => r.amount.any (· > cap)))),
   (.CUMULATIVE_AMOUNT_EXCEEDED, selectedIds (fun p => (usageFor c p.authorityId).any (fun u =>
      p.constraints.maxCumulativeAmount.any (fun cap => r.amount.any (fun a => u.admittedCumulativeAmount + a > cap))))),
   (.AMOUNT_OVERFLOW, selectedIds (fun p => (format2Usage.find? (fun u => u.authorityId == p.authorityId)).any (fun u =>
      r.amount.any (fun amount => u.admittedCumulativeAmount + amount > maxAmount) ||
        u.admittedTransactionCount >= maxU53))),
   (.TRANSACTION_COUNT_EXCEEDED, selectedIds (fun p => (usageFor c p.authorityId).any (fun u =>
      p.constraints.maxTransactions.any (u.admittedTransactionCount >= ·)))),
   (.NO_AUTHORITY, selectedIds (fun p => inactive c p.grantorId || inactive c p.granteeId))]

def evaluateCandidate (format2Usage : List Usage) (c : Corpus) (paths : List Path) (globals : List Prohibition)
    (main : Path) (r : Request) (t : Nat) : Except Failure Candidate :=
  if (recognize c main).isNone then .error (candidateFailure main .NO_AUTHORITY main.rootId)
  else
    let graph := selectGraph c paths main r.actorId
    let relevant := c.prohibitions.filter (fun p => prohibitionApplies p graph r)
    let matching :=  relevant.filter (fun p => prohibitionActive c paths p t && prohibitionAmount p r)
    match (sorted (matching.map (·.authorityId))).head? with
    | some id => .error (candidateFailure main .PROHIBITED id)
    | none => match firstFailure (failureSets format2Usage c graph r t) with
      | some (code, id) => .error (candidateFailure main code id)
      | none => .ok {
          graph := graph
          checkedProhibitionIds := union ((globals ++ relevant).map (·.authorityId)) }

def rank : Code → Nat
  | .PROHIBITED => 1 | .REVOKED => 2 | .NOT_YET_VALID => 3 | .EXPIRED => 4
  | .MISSING_INTERSECTION => 5 | .ACTION_NOT_ALLOWED => 6 | .RESOURCE_NOT_ALLOWED => 7
  | .AMOUNT_REQUIRED => 8 | .AMOUNT_EXCEEDED => 9 | .CUMULATIVE_AMOUNT_EXCEEDED => 10
  | .AMOUNT_OVERFLOW => 11 | .TRANSACTION_COUNT_EXCEEDED => 12 | .NO_AUTHORITY => 13 | _ => 0

def compareFailure (a b : Failure) : Ordering :=
  firstOrdering [compare (rank a.code) (rank b.code), compareOpt a.rootAuthorityId b.rootAuthorityId,
    compareOpt a.terminalAuthorityId b.terminalAuthorityId, compareOpt a.failingAuthorityId b.failingAuthorityId,
    compareIds a.authorityPathIds b.authorityPathIds, compareOpt a.subjectId b.subjectId]

def evaluateAlgebra (format2Usage : List Usage) (c : Corpus) (paths : List Path) (r : Request) (t : Nat)
    (adminOK : Path → Bool := fun _ => true) : Decision :=
  let globals := c.prohibitions.filter (fun p => p.scope == .GLOBAL && prohibitionRelevant p r)
  match (sorted ((globalMatches c paths r t).map (·.authorityId))).head? with
  | some id => .deny [{ code := .PROHIBITED, subjectId := some r.actorId, failingAuthorityId := some id }]
  | none =>
    let candidates := paths.filter (fun p => p.independent && p.terminal.granteeId == r.actorId && adminOK p)
    let results := candidates.map (fun p => evaluateCandidate format2Usage c paths globals p r t)
    let successes := results.filterMap (fun r => match r with | .ok x => some x | _ => none)
    match (successes.mergeSort (fun a b => compareCandidate a b != .gt)).head? with
    | some winner => .allow winner
    | none => if candidates.isEmpty then deny .NO_AUTHORITY (some r.actorId)
      else .deny ((results.filterMap (fun r => match r with | .error x => some x | _ => none)).mergeSort
        (fun a b => compareFailure a b != .gt))

/-- A-137.3 native-format reservation collision. Legacy shadow mode is excluded. -/
def nonceCollision (reservations : List NonceReservation) (actor nonce intent : Id) : Bool :=
  reservations.any (fun n => n.actorId == actor && n.nonce == nonce && n.intentId != intent)

/-- Result after the specified nonce check, before proof-size preflight.
    Session/binding/budget and replay admission are outside this component. -/
def afterNonce (collision : Bool) : Decision → Decision
  | .allow a => if collision then deny .NONCE_ALREADY_ADMITTED else .allow a
  | other => other

def allows : Decision → Bool
  | .allow _ => true
  | _ => false

/-- A-133 diagnostic final-decision projection. Its correspondence theorem is
    restricted to actual finalize output; an arbitrary externally supplied
    OUTPUT_LIMIT_EXCEEDED result is not proof of a successful candidate. -/
def revisedAllow : Decision → Bool
  | .allow _ => true
  | .indeterminate .OUTPUT_LIMIT_EXCEEDED => true
  | _ => false

end Authority.G65
