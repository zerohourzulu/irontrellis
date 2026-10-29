import Std

/- Executable model derived only from r4 §8 and inherited spec02.
   Initial independent phase: no authority.ts or oracle source consulted.
   Natural numbers represent successfully decoded nonnegative scalar values;
   outer host capture/replay/signature validity are explicit boundary facts. -/
namespace Authority
abbrev Id := String
abbrev Amount := Nat
def maxU53 : Nat := 2^53 - 1
def maxAmount : Nat := 2^256 - 1

inductive Code where
  | DOMAIN_MISMATCH | POLICY_MISMATCH | INVALID_REQUEST | INVALID_AMOUNT
  | INVALID_DELEGATION | AGENT_INACTIVE | SESSION_NOT_FOUND | SESSION_EXPIRED
  | SESSION_CREDENTIAL_REQUIRED | SESSION_CREDENTIAL_INVALID | SESSION_FENCED
  | STALE_EPOCH | ROLE_TENURE_NOT_CURRENT | INTENT_REQUIRED | INTENT_NOT_DECLARED
  | INTENT_MISMATCH | INTENT_REPLAY | NONCE_ALREADY_ADMITTED | PROHIBITED
  | REVOKED | NOT_YET_VALID | EXPIRED | MISSING_INTERSECTION | ACTION_NOT_ALLOWED
  | RESOURCE_NOT_ALLOWED | AMOUNT_REQUIRED | AMOUNT_EXCEEDED
  | CUMULATIVE_AMOUNT_EXCEEDED | TRANSACTION_COUNT_EXCEEDED | NO_AUTHORITY
  | INVALID_INPUT | UNSUPPORTED_VERSION | OUTPUT_LIMIT_EXCEEDED
  | STATE_NOT_AUTHORITATIVE | CAUSAL_TIME_INVALID | HISTORY_RELATION_UNVERIFIED
  | EVIDENCE_UNAVAILABLE | EVIDENCE_DISPUTED | AMOUNT_OVERFLOW
  deriving BEq, Repr, DecidableEq, Inhabited

def codeName (c : Code) : String := (repr c).pretty.replace "Authority.Code." ""
inductive Validity where | valid | invalid | limit
  deriving BEq, Repr, DecidableEq, Inhabited

def merge (a b : Validity) : Validity :=
  if a == .limit || b == .limit then .limit
  else if a == .invalid || b == .invalid then .invalid else .valid

def identifierStatus (s : String) : Validity :=
  if s.utf8ByteSize > 256 then .limit
  else if s.isEmpty || s.toList.any (fun c => c.toNat < 32 || c.toNat == 127) then .invalid
  else .valid

def distinct [BEq α] (xs : List α) : Bool := xs.length == xs.eraseDups.length

def distinctValidIds (xs : List Id) : Bool := distinct (xs.filter (fun id => identifierStatus id == .valid))

def idsStatus (xs : List Id) (bound : Nat) (nonempty := false) : Validity :=
  let scalar := xs.foldl (fun a s => merge a (identifierStatus s)) .valid
  merge scalar (if xs.length > bound then .limit
    else if (nonempty && xs.isEmpty) || !distinct xs then .invalid else .valid)

def natStatus (n : Nat) (bound : Nat) : Validity := if n > bound then .limit else .valid

def optionStatus (f : α → Validity) : Option α → Validity
  | none => .valid | some x => f x

def idLt (a b : Id) : Bool := decide (a.toUTF8.data.toList < b.toUTF8.data.toList)
def sorted (xs : List Id) : List Id := xs.mergeSort (fun a b => !idLt b a)
def union (xs : List Id) : List Id := sorted xs.eraseDups

def subset (a b : List Id) : Bool := a.all b.contains

def lowerBound (parent child : Option Nat) : Bool :=
  match parent, child with
  | none, _ => true | some _, none => false | some p, some c => p <= c

def upperBound (parent child : Option Nat) : Bool :=
  match parent, child with
  | none, _ => true | some _, none => false | some p, some c => c <= p

structure Constraints where
  actions : List Id := []
  resources : List Id := []
  quantitative : Bool := false
  notBefore : Option Nat := none
  expiresAt : Option Nat := none
  maxAmount : Option Nat := none
  maxCumulativeAmount : Option Nat := none
  maxTransactions : Option Nat := none
  maxDelegationDepth : Nat := 0
  requiredIntersectionIds : List Id := []
  deriving BEq, Repr, Inhabited

def constraintsStatus (c : Constraints) : Validity :=
  [idsStatus c.actions 256 true, idsStatus c.resources 256 true,
   idsStatus c.requiredIntersectionIds 32,
   optionStatus (fun n => natStatus n maxU53) c.notBefore,
   optionStatus (fun n => natStatus n maxU53) c.expiresAt,
   optionStatus (fun n => natStatus n maxAmount) c.maxAmount,
   optionStatus (fun n => natStatus n maxAmount) c.maxCumulativeAmount,
   optionStatus (fun n => natStatus n maxU53) c.maxTransactions,
   natStatus c.maxDelegationDepth maxU53,
   if (!c.quantitative && (c.maxAmount.isSome || c.maxCumulativeAmount.isSome)) ||
       (match c.notBefore, c.expiresAt with | some a, some b => a >= b | _, _ => false)
   then .invalid else .valid].foldl merge .valid

/-- spec02 §3.3, including inherited intersection requirements. -/
def attenuated (p c : Constraints) : Bool :=
  subset c.actions p.actions && subset c.resources p.resources &&
  subset p.requiredIntersectionIds c.requiredIntersectionIds &&
  p.maxDelegationDepth > 0 && c.maxDelegationDepth < p.maxDelegationDepth &&
  (!p.quantitative || c.quantitative) && lowerBound p.notBefore c.notBefore &&
  upperBound p.expiresAt c.expiresAt && upperBound p.maxAmount c.maxAmount &&
  upperBound p.maxCumulativeAmount c.maxCumulativeAmount &&
  upperBound p.maxTransactions c.maxTransactions

structure Permission where
  authorityId : Id := ""
  grantorId : Id := ""
  granteeId : Id := ""
  rootAuthorityId : Id := ""
  parentAuthorityId : Option Id := none
  independent : Bool := true
  constraints : Constraints := {}
  deriving BEq, Repr, Inhabited

inductive ProhibitionScope where | ROOT | GLOBAL deriving BEq, Repr, Inhabited
structure Prohibition where
  authorityId : Id := ""
  grantorId : Id := ""
  subjectActorId : Option Id := none
  scope : ProhibitionScope := .ROOT
  rootAuthorityId : Option Id := none
  parentAuthorityId : Option Id := none
  constraints : Constraints := {}
  deriving BEq, Repr, Inhabited

structure Root where
  rootAuthorityId : Id := ""
  principalId : Id := ""
  principalRecognitionEventId : Id := ""
  rootGrantEventId : Id := ""
  deriving BEq, Repr, Inhabited
structure Evidence where
  authorityId : Id := ""
  grantEventId : Id := ""
  grantEventPosition : Nat := 0
  deriving BEq, Repr, Inhabited
structure Usage where
  authorityId : Id := ""
  admittedTransactionCount : Nat := 0
  admittedCumulativeAmount : Nat := 0
  deriving BEq, Repr, Inhabited
structure Agent where
  id : Id := ""
  principalId : Id := ""
  controllerId : Id := ""
  currentControlEpoch : Nat := 1
  terminated : Bool := false
  deriving BEq, Repr, Inhabited
structure Principal where
  id : Id := ""
  creationEventId : Id := ""
  deriving BEq, Repr, Inhabited
structure Corpus where
  permissions : List Permission := []
  prohibitions : List Prohibition := []
  roots : List Root := []
  evidence : List Evidence := []
  revoked : List Id := []
  usage : List Usage := []
  globalPolicySourceId : Id := "global"
  agents : Option (List Agent) := none
  principals : Option (List Principal) := none
  /-- Optional accepted-replay authority records, represented by their grant evidence. -/
  replayRecords : Option (List Evidence) := none
  deriving BEq, Repr, Inhabited

structure Path where
  grants : List Permission := []
  deriving BEq, Repr, Inhabited

def Path.ids (p : Path) : List Id := p.grants.map (·.authorityId)
def Path.rootId (p : Path) : Id := (p.grants.headD {}).rootAuthorityId
def Path.terminal (p : Path) : Permission := p.grants.getLastD {}
def Path.independent (p : Path) : Bool := p.grants.all (·.independent)
def permission (c : Corpus) (id : Id) : Option Permission := c.permissions.find? (·.authorityId == id)
def usageFor (c : Corpus) (id : Id) : Option Usage := c.usage.find? (·.authorityId == id)
def inactive (c : Corpus) (id : Id) : Bool :=
  ((c.agents.getD []).find? (·.id == id)).any (·.terminated)

def buildUp (c : Corpus) : Nat → List Id → Permission → Except Code (List Permission)
  | 0, _, _ => .error .INVALID_INPUT
  | fuel+1, seen, g =>
    if seen.contains g.authorityId then .error .INVALID_DELEGATION
    else match g.parentAuthorityId with
      | none => .ok [g]
      | some id => match permission c id with
        | none => .error .INVALID_DELEGATION
        | some parent => do
          let ancestors ← buildUp c fuel (g.authorityId :: seen) parent
          pure (ancestors ++ [g])

def pathLinksValid : List Permission → Bool
  | [] => true | [_] => true
  | p :: c :: rest => c.grantorId == p.granteeId && c.rootAuthorityId == p.rootAuthorityId &&
      attenuated p.constraints c.constraints && pathLinksValid (c :: rest)

def buildPath (c : Corpus) (g : Permission) : Except Code Path := do
  let gs ← buildUp c 32 [] g
  if pathLinksValid gs then pure ⟨gs⟩ else .error .INVALID_DELEGATION

/-- DFS stacks distinguish cycles from sharing; unknown partners do not create edges. -/
def intersectionCycle (c : Corpus) : Nat → List Id → Id → Bool
  | 0, _, _ => true
  | fuel+1, stack, id =>
    if stack.contains id then true
    else match permission c id with
      | none => false
      | some g => g.constraints.requiredIntersectionIds.any fun next =>
          (permission c next).isSome && intersectionCycle c fuel (id :: stack) next

def recognize (c : Corpus) (p : Path) : Option Root :=
  c.roots.find? fun r => r.rootAuthorityId == p.rootId &&
    (p.grants.head?).any (fun g => g.authorityId == r.rootAuthorityId &&
      g.rootAuthorityId == r.rootAuthorityId && g.grantorId == r.principalId &&
      g.parentAuthorityId.isNone)

def permissionStatus (g : Permission) : Validity :=
  [identifierStatus g.authorityId, identifierStatus g.grantorId,
   identifierStatus g.granteeId, identifierStatus g.rootAuthorityId,
   optionStatus identifierStatus g.parentAuthorityId, constraintsStatus g.constraints].foldl merge .valid

def prohibitionStatus (g : Prohibition) : Validity :=
  let shape := if !g.constraints.requiredIntersectionIds.isEmpty ||
    g.constraints.maxDelegationDepth != 0 || g.constraints.maxCumulativeAmount.isSome ||
    g.constraints.maxTransactions.isSome ||
    (g.scope == .GLOBAL && (g.rootAuthorityId.isSome || g.parentAuthorityId.isSome)) ||
    (g.scope == .ROOT && g.rootAuthorityId.isNone) then .invalid else .valid
  [shape, identifierStatus g.authorityId, identifierStatus g.grantorId,
   optionStatus identifierStatus g.subjectActorId, optionStatus identifierStatus g.rootAuthorityId,
   optionStatus identifierStatus g.parentAuthorityId, constraintsStatus g.constraints].foldl merge .valid

def corpusStatus (c : Corpus) : Validity :=
  let grantIds := c.permissions.map (·.authorityId) ++ c.prohibitions.map (·.authorityId)
  let rootIds := c.roots.map (·.rootAuthorityId)
  let evidenceIds := c.evidence.map (·.authorityId)
  let usageIds := c.usage.map (·.authorityId)
  let initial := if grantIds.length > 1024 || !distinctValidIds rootIds || !distinctValidIds evidenceIds ||
      !distinctValidIds usageIds || !distinctValidIds c.revoked then .limit
    else if !distinct grantIds then .invalid else .valid
  let statuses := c.permissions.map permissionStatus ++ c.prohibitions.map prohibitionStatus ++
    c.roots.flatMap (fun r => [identifierStatus r.rootAuthorityId, identifierStatus r.principalId,
      identifierStatus r.principalRecognitionEventId, identifierStatus r.rootGrantEventId]) ++
    c.evidence.flatMap (fun e => [identifierStatus e.authorityId, identifierStatus e.grantEventId,
      natStatus e.grantEventPosition maxU53]) ++
    c.usage.flatMap (fun u => [identifierStatus u.authorityId,
      natStatus u.admittedTransactionCount maxU53, natStatus u.admittedCumulativeAmount maxAmount]) ++
    c.revoked.map identifierStatus
  statuses.foldl merge initial

def rootValid (c : Corpus) (r : Root) : Bool :=
  match permission c r.rootAuthorityId, c.evidence.find? (·.authorityId == r.rootAuthorityId) with
  | some g, some e => g.parentAuthorityId.isNone && g.authorityId == r.rootAuthorityId &&
      g.rootAuthorityId == r.rootAuthorityId && g.grantorId == r.principalId &&
      e.grantEventId == r.rootGrantEventId &&
      (match c.principals with
       | none => true
       | some ps => (ps.find? (·.id == r.principalId)).any (·.creationEventId == r.principalRecognitionEventId)) &&
      (match c.replayRecords with
       | none => true
       | some rs => (rs.find? (·.authorityId == r.rootAuthorityId)).any (fun rec =>
          rec.grantEventId == r.rootGrantEventId && rec.grantEventPosition == e.grantEventPosition))
  | _, _ => false

def prohibitionValid (c : Corpus) (paths : List Path) (p : Prohibition) : Bool :=
  if p.scope == .GLOBAL then p.grantorId == c.globalPolicySourceId
  else match c.roots.find? (fun r => some r.rootAuthorityId == p.rootAuthorityId) with
    | none => false
    | some r => if p.grantorId == r.principalId then p.parentAuthorityId.isNone &&
        (permission c r.rootAuthorityId).any (fun g => attenuated g.constraints p.constraints)
      else match p.parentAuthorityId with
        | none => false
        | some anchor => (permission c anchor).any (fun g => g.granteeId == p.grantorId &&
            attenuated g.constraints p.constraints) &&
          (paths.find? (fun q => q.terminal.authorityId == anchor)).any (fun q => some q.rootId == p.rootAuthorityId)

def corpusRelationsValid (c : Corpus) (paths : List Path) : Bool :=
  let grantIds := c.permissions.map (·.authorityId) ++ c.prohibitions.map (·.authorityId)
  let evIds := c.evidence.map (·.authorityId)
  let capped := (c.permissions.filter fun p =>
      p.constraints.maxTransactions.isSome || p.constraints.maxCumulativeAmount.isSome).map (·.authorityId)
  let usageIds := c.usage.map (·.authorityId)
  evIds.length == grantIds.length && subset grantIds evIds && subset evIds grantIds &&
  c.roots.all (rootValid c) && c.prohibitions.all (prohibitionValid c paths) &&
  subset c.revoked grantIds && subset capped usageIds && subset usageIds capped

/-- Sink elimination detects cycles without exponential revisits through shared
    DAG partners. Unknown IDs are absent from the active vertex set. At most N
    strict vertex-count decreases precede either emptiness or a fixed point. -/
def intersectionCycleKahn : Nat → List Permission → Bool
  | 0, remaining => !remaining.isEmpty
  | fuel+1, remaining =>
    if remaining.isEmpty then false
    else
      let ids := remaining.foldl (fun acc p => acc.insert p.authorityId) ({} : Std.HashSet Id)
      let next := remaining.filter fun p => p.constraints.requiredIntersectionIds.any ids.contains
      if next.length == remaining.length then true else intersectionCycleKahn fuel next

def validateCorpus (c : Corpus) : Except Code (List Path) := do
  let paths ← c.permissions.mapM (buildPath c)
  if intersectionCycleKahn (c.permissions.length + 1) c.permissions
    then .error .INVALID_DELEGATION
  else if corpusRelationsValid c paths then .ok paths else .error .INVALID_DELEGATION

structure Request where
  actorId : Id := ""
  action : Id := ""
  resource : Id := ""
  claimedAt : Nat := 0
  amount : Option Nat := none
  counterpartyId : Option Id := none
  termsCommitment : Option Id := none
  deriving BEq, Repr, Inhabited

def contentHashValid (s : String) : Bool :=
  s.length == 66 && s.startsWith "0x" && (s.toList.drop 2).all fun c =>
    c >= '0' && c <= '9' || c >= 'a' && c <= 'f'

def requestProblem (r : Request) : Option Code :=
  if [r.actorId, r.action, r.resource].any (fun s => identifierStatus s != .valid) ||
      r.claimedAt > maxU53 || r.counterpartyId.any (fun s => identifierStatus s != .valid) ||
      r.termsCommitment.any (fun s => !contentHashValid s) then some .INVALID_REQUEST
  else if r.amount.any (· > maxAmount) then some .INVALID_AMOUNT else none

structure Requirement where
  requiredId : Id
  requiredBy : Id
  deriving BEq, Repr, Inhabited

def directRequirementsAux (previous : List Id) : List Permission → List Requirement
  | [] => []
  | g :: gs => (g.constraints.requiredIntersectionIds.filter (fun id => !previous.contains id)).map
      (fun id => ⟨id, g.authorityId⟩) ++ directRequirementsAux g.constraints.requiredIntersectionIds gs

def directRequirements (p : Path) : List Requirement := directRequirementsAux [] p.grants
structure Graph where
  main : Path := {}
  partners : List Path := []
  requirements : List Requirement := []
  missing : List Id := []
  deriving BEq, Repr, Inhabited

def Graph.paths (g : Graph) : List Path := g.main :: g.partners
def Graph.grants (g : Graph) : List Permission := g.paths.flatMap (·.grants)
def Graph.controlling (g : Graph) : List Id := union (g.grants.map (·.authorityId))

def selectLoop (c : Corpus) (paths : List Path) (actor : Id) :
    Nat → List Id → List Requirement → Graph → Graph
  | 0, _, [], graph => graph
  | 0, _, queue, graph => { graph with missing := graph.missing ++ queue.map (·.requiredId) }
  | _+1, _, [], graph => graph
  | fuel+1, seen, req :: queue, graph =>
    let graph := { graph with requirements := graph.requirements ++ [req] }
    if seen.contains req.requiredId then selectLoop c paths actor fuel seen queue graph
    else
      let seen := req.requiredId :: seen
      match paths.find? (fun p => p.terminal.authorityId == req.requiredId) with
      | none => selectLoop c paths actor fuel seen queue { graph with missing := req.requiredId :: graph.missing }
      | some p =>
        if (recognize c p).isNone || p.independent || p.terminal.granteeId != actor then
          selectLoop c paths actor fuel seen queue { graph with missing := req.requiredId :: graph.missing }
        else selectLoop c paths actor fuel seen (queue ++ directRequirements p)
          { graph with partners := graph.partners ++ [p] }

def selectGraph (c : Corpus) (paths : List Path) (main : Path) (actor : Id) : Graph :=
  let g := selectLoop c paths actor ((c.permissions.length + 1) * 1024 + 1) []
    (directRequirements main) { main := main }
  { g with
    missing := union g.missing
    partners := g.partners.mergeSort (fun a b => !idLt b.terminal.authorityId a.terminal.authorityId) }

def inWindow (c : Constraints) (t : Nat) : Bool :=
  !c.notBefore.any (t < ·) && !c.expiresAt.any (t >= ·)

def pathActive (c : Corpus) (p : Path) (t : Nat) : Bool :=
  p.grants.all (fun g => !c.revoked.contains g.authorityId && inWindow g.constraints t &&
    !inactive c g.grantorId && !inactive c g.granteeId)

def prohibitionRelevant (p : Prohibition) (r : Request) : Bool :=
  (p.subjectActorId.isNone || p.subjectActorId == some r.actorId) &&
  p.constraints.actions.contains r.action && p.constraints.resources.contains r.resource &&
  (!p.constraints.quantitative || r.amount.isSome)

def prohibitionActive (c : Corpus) (paths : List Path) (p : Prohibition) (t : Nat) : Bool :=
  !c.revoked.contains p.authorityId && inWindow p.constraints t &&
  (if p.scope == .GLOBAL then true else match p.parentAuthorityId with
    | none => true
    | some anchor => (paths.find? (fun q => q.terminal.authorityId == anchor)).any (fun q => pathActive c q t))

def prohibitionAmount (p : Prohibition) (r : Request) : Bool :=
  match p.constraints.maxAmount with | none => true | some n => r.amount.any (· <= n)

def prohibitionApplies (p : Prohibition) (g : Graph) (r : Request) : Bool :=
  p.scope == .ROOT && prohibitionRelevant p r && g.paths.any fun path =>
    some path.rootId == p.rootAuthorityId &&
    (p.parentAuthorityId.isNone || p.parentAuthorityId.any path.ids.contains)

structure Failure where
  code : Code := .NO_AUTHORITY
  subjectId : Option Id := none
  rootAuthorityId : Option Id := none
  terminalAuthorityId : Option Id := none
  failingAuthorityId : Option Id := none
  authorityPathIds : List Id := []
  deriving BEq, Repr, Inhabited

/-- Twelve complete failure sets in normative order (A-135/A-156.1/A-166/A-178.2).
    Overflow reads the separate format-2 ledger; legacy caps read corpus.usage
    (A-200). Corpus-only callers explicitly use the default empty format-2 ledger. -/
def failureSets (c : Corpus) (g : Graph) (r : Request) (t : Nat)
    (format2Usage : List Usage := []) : List (Code × List Id) :=
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
   (.AMOUNT_OVERFLOW, selectedIds (fun p =>
      (format2Usage.find? (fun u => u.authorityId == p.authorityId)).any (fun u =>
        r.amount.any (fun amount => u.admittedCumulativeAmount + amount > maxAmount) ||
        u.admittedTransactionCount >= maxU53))),
   (.TRANSACTION_COUNT_EXCEEDED, selectedIds (fun p => (usageFor c p.authorityId).any (fun u =>
      p.constraints.maxTransactions.any (u.admittedTransactionCount >= ·)))),
   (.NO_AUTHORITY, selectedIds (fun p => inactive c p.grantorId || inactive c p.granteeId))]

def firstFailure (sets : List (Code × List Id)) : Option (Code × Id) :=
  match sets with
  | [] => none
  | (code, ids) :: rest => match (sorted ids).head? with
    | none => firstFailure rest | some id => some (code, id)

structure Candidate where
  graph : Graph := {}
  checkedProhibitionIds : List Id := []
  deriving BEq, Repr, Inhabited

def candidateFailure (main : Path) (code : Code) (id : Id) : Failure :=
  { code := code, rootAuthorityId := some main.rootId,
    terminalAuthorityId := some main.terminal.authorityId,
    failingAuthorityId := some id, authorityPathIds := main.ids }

def evaluateCandidate (c : Corpus) (paths : List Path) (globals : List Prohibition)
    (main : Path) (r : Request) (t : Nat) (format2Usage : List Usage := []) : Except Failure Candidate :=
  if (recognize c main).isNone then .error (candidateFailure main .NO_AUTHORITY main.rootId)
  else
    let graph := selectGraph c paths main r.actorId
    let relevant := c.prohibitions.filter (fun p => prohibitionApplies p graph r)
    let matching :=  relevant.filter (fun p => prohibitionActive c paths p t && prohibitionAmount p r)
    match (sorted (matching.map (·.authorityId))).head? with
    | some id => .error (candidateFailure main .PROHIBITED id)
    | none => match firstFailure (failureSets c graph r t (format2Usage := format2Usage)) with
      | some (code, id) => .error (candidateFailure main code id)
      | none => .ok {
          graph := graph
          checkedProhibitionIds := union ((globals ++ relevant).map (·.authorityId)) }

def rank : Code → Nat
  | .PROHIBITED => 1 | .REVOKED => 2 | .NOT_YET_VALID => 3 | .EXPIRED => 4
  | .MISSING_INTERSECTION => 5 | .ACTION_NOT_ALLOWED => 6 | .RESOURCE_NOT_ALLOWED => 7
  | .AMOUNT_REQUIRED => 8 | .AMOUNT_EXCEEDED => 9 | .CUMULATIVE_AMOUNT_EXCEEDED => 10
  | .AMOUNT_OVERFLOW => 11 | .TRANSACTION_COUNT_EXCEEDED => 12 | .NO_AUTHORITY => 13 | _ => 0

def compareIds : List Id → List Id → Ordering
  | [], [] => .eq | [], _::_ => .lt | _::_, [] => .gt
  | a::as, b::bs => if idLt a b then .lt else if idLt b a then .gt else compareIds as bs

def compareOpt (a b : Option Id) : Ordering := compareIds a.toList b.toList

def firstOrdering : List Ordering → Ordering
  | [] => .eq | .eq :: rest => firstOrdering rest | x :: _ => x

def compareFailure (a b : Failure) : Ordering :=
  firstOrdering [compare (rank a.code) (rank b.code), compareOpt a.rootAuthorityId b.rootAuthorityId,
    compareOpt a.terminalAuthorityId b.terminalAuthorityId, compareOpt a.failingAuthorityId b.failingAuthorityId,
    compareIds a.authorityPathIds b.authorityPathIds, compareOpt a.subjectId b.subjectId]

/-- Validated unique terminal IDs make main-path ties impossible, so the spec's
    later hash tie-breakers are unreachable for distinct candidates. -/
def compareCandidate (a b : Candidate) : Ordering :=
  firstOrdering [compareIds [a.graph.main.rootId] [b.graph.main.rootId],
    compareIds a.graph.main.ids b.graph.main.ids]

inductive Decision where
  | allow (candidate : Candidate)
  | deny (failures : List Failure)
  | indeterminate (code : Code)
  deriving BEq, Repr, Inhabited

def deny (code : Code) (subject : Option Id := none) : Decision :=
  .deny [{ code := code, subjectId := subject }]

def globalMatches (c : Corpus) (paths : List Path) (r : Request) (t : Nat) : List Prohibition :=
  c.prohibitions.filter fun p => p.scope == .GLOBAL && prohibitionRelevant p r &&
    prohibitionActive c paths p t && prohibitionAmount p r

def evaluateAlgebra (c : Corpus) (paths : List Path) (r : Request) (t : Nat)
    (adminOK : Path → Bool := fun _ => true) (format2Usage : List Usage := []) : Decision :=
  let globals := c.prohibitions.filter (fun p => p.scope == .GLOBAL && prohibitionRelevant p r)
  match (sorted ((globalMatches c paths r t).map (·.authorityId))).head? with
  | some id => .deny [{ code := .PROHIBITED, subjectId := some r.actorId, failingAuthorityId := some id }]
  | none =>
    let candidates := paths.filter (fun p => p.independent && p.terminal.granteeId == r.actorId && adminOK p)
    let results := candidates.map (fun p => evaluateCandidate c paths globals p r t (format2Usage := format2Usage))
    let successes := results.filterMap (fun r => match r with | .ok x => some x | _ => none)
    match (successes.mergeSort (fun a b => compareCandidate a b != .gt)).head? with
    | some winner => .allow winner
    | none => if candidates.isEmpty then deny .NO_AUTHORITY (some r.actorId)
      else .deny ((results.filterMap (fun r => match r with | .error x => some x | _ => none)).mergeSort
        (fun a b => compareFailure a b != .gt))

def optMin (a b : Option Nat) : Option Nat :=
  match a,b with | none,x => x | x,none => x | some x,some y => some (min x y)
def optMax (a b : Option Nat) : Option Nat :=
  match a,b with | none,x => x | x,none => x | some x,some y => some (max x y)

def combinePair (a b : Constraints) : Constraints :=
  { actions := a.actions.filter b.actions.contains,
    resources := a.resources.filter b.resources.contains,
    quantitative := a.quantitative || b.quantitative,
    notBefore := optMax a.notBefore b.notBefore, expiresAt := optMin a.expiresAt b.expiresAt,
    maxAmount := optMin a.maxAmount b.maxAmount,
    maxCumulativeAmount := optMin a.maxCumulativeAmount b.maxCumulativeAmount,
    maxTransactions := optMin a.maxTransactions b.maxTransactions,
    maxDelegationDepth := min a.maxDelegationDepth b.maxDelegationDepth,
    requiredIntersectionIds := union (a.requiredIntersectionIds ++ b.requiredIntersectionIds) }

def combineConstraints (gs : List Permission) : Constraints :=
  match gs with
  | [] => {}
  | g::rest => rest.foldl (fun a p => combinePair a p.constraints)
      { g.constraints with
        actions := sorted g.constraints.actions
        resources := sorted g.constraints.resources
        requiredIntersectionIds := sorted g.constraints.requiredIntersectionIds }

def proofFits (c : Corpus) (a : Candidate) : Bool :=
  let paths := a.graph.paths
  let effective := combineConstraints a.graph.grants
  let effectiveFits (x : Constraints) := x.actions.length <= 256 && x.resources.length <= 256 &&
    x.requiredIntersectionIds.length <= 256
  let controlling := a.graph.controlling
  !a.graph.main.grants.isEmpty && a.graph.partners.length <= 256 &&
  a.checkedProhibitionIds.length <= 256 && effectiveFits effective &&
  paths.all (fun p => !p.grants.isEmpty && p.grants.length <= 32 &&
    p.grants.all (fun g => g.constraints.actions.length <= 256 && g.constraints.resources.length <= 256 &&
      g.constraints.requiredIntersectionIds.length <= 32)) &&
  controlling.length <= 256 && a.graph.partners.all (fun p =>
    let requiredByIds := union ((a.graph.requirements.filter (·.requiredId == p.terminal.authorityId)).map (·.requiredBy))
    !requiredByIds.isEmpty && requiredByIds.length <= 256 && effectiveFits (combineConstraints p.grants)) &&
  (c.usage.filter (fun u => controlling.contains u.authorityId)).length <= 256 &&
  (union (controlling ++ a.checkedProhibitionIds)).length <= 1024

def finalize (c : Corpus) : Decision → Decision
  | .allow a => if proofFits c a then .allow a else .indeterminate .OUTPUT_LIMIT_EXCEEDED
  | result => result

/-- Typed portion of spec02 §2.2 phase-one capture and §7.1 step2.
    Unlike semantic validation, these limits precede causal time and requests. -/
def constraintsCaptureLimit (c : Constraints) : Bool :=
  c.actions.length > 256 || c.resources.length > 256 || c.requiredIntersectionIds.length > 32 ||
  (c.actions ++ c.resources ++ c.requiredIntersectionIds).any (fun id => identifierStatus id == .limit)

def requestCaptureLimit (r : Request) : Bool :=
  ([r.actorId, r.action, r.resource] ++ r.counterpartyId.toList).any (fun id => identifierStatus id == .limit)

def rawCaptureLimit (c : Corpus) (r : Request) : Bool :=
  c.permissions.length + c.prohibitions.length > 1024 ||
  [c.roots.length,c.evidence.length,c.usage.length,c.revoked.length].any (· > 4096) ||
  !distinctValidIds (c.roots.map (·.rootAuthorityId)) || !distinctValidIds (c.evidence.map (·.authorityId)) ||
  !distinctValidIds (c.usage.map (·.authorityId)) || !distinctValidIds c.revoked || requestCaptureLimit r ||
  identifierStatus c.globalPolicySourceId == .limit ||
  c.permissions.any (fun p => constraintsCaptureLimit p.constraints ||
    ([p.authorityId,p.grantorId,p.granteeId,p.rootAuthorityId] ++ p.parentAuthorityId.toList).any
      (fun id => identifierStatus id == .limit)) ||
  c.prohibitions.any (fun p => constraintsCaptureLimit p.constraints ||
    ([p.authorityId,p.grantorId] ++ p.rootAuthorityId.toList ++ p.parentAuthorityId.toList ++ p.subjectActorId.toList).any
      (fun id => identifierStatus id == .limit)) ||
  c.roots.any (fun r => [r.rootAuthorityId,r.principalId,r.principalRecognitionEventId,r.rootGrantEventId].any
      (fun id => identifierStatus id == .limit)) ||
  c.evidence.any (fun e => [e.authorityId,e.grantEventId].any (fun id => identifierStatus id == .limit)) ||
  c.usage.any (fun u => identifierStatus u.authorityId == .limit) ||
  c.revoked.any (fun id => identifierStatus id == .limit) ||
  (let unique := c.permissions.filter fun p => (c.permissions.filter (·.authorityId == p.authorityId)).length == 1
   let unambiguous := { c with permissions := unique }
   unique.any (fun p => match buildUp unambiguous 32 [] p with | .error .INVALID_INPUT => true | _ => false))

/-- Raw typed entry: host record capture is handled by the boundary, values here
    still undergo all semantic and bound checks. -/
def evaluateRaw (c : Corpus) (r : Request) (t headTime : Nat)
    (policyValid := true) : Decision :=
  if rawCaptureLimit c r then .indeterminate .INVALID_INPUT
  else if t > maxU53 || t < headTime then .indeterminate .CAUSAL_TIME_INVALID
  else if !policyValid then deny .POLICY_MISMATCH
  else match requestProblem r with
    | some code => deny code
    | none => match corpusStatus c with
      | .limit => .indeterminate .INVALID_INPUT
      | .invalid => deny .INVALID_DELEGATION
      | .valid => match validateCorpus c with
        | .error .INVALID_INPUT => .indeterminate .INVALID_INPUT
        | .error _ => deny .INVALID_DELEGATION
        | .ok paths => finalize c (evaluateAlgebra c paths r t (format2Usage := c.usage))

structure Domain where
  protocol : String := "continuity"
  version : String := "2"
  deploymentId : Id := ""
  chainId : String := "1"
  verifyingContract : String := ""
  deriving BEq, Repr, Inhabited
structure Head where
  hash : String := ""
  position : Nat := 0
  canonicalTime : Nat := 0
  deriving BEq, Repr, Inhabited
structure Session where
  id : Id := ""
  agentId : Id := ""
  controllerId : Id := ""
  controlEpoch : Nat := 1
  credentialKeyId : Id := ""
  expiresAt : Option Nat := none
  deriving BEq, Repr, Inhabited
structure Role where
  id : Id := ""
  principalId : Id := ""
  currentTenureId : Option Id := none
  deriving BEq, Repr, Inhabited
structure Tenure where
  id : Id := ""
  roleId : Id := ""
  agentId : Id := ""
  principalId : Id := ""
  tenureNumber : Nat := 1
  closed : Bool := false
  deriving BEq, Repr, Inhabited
structure Binding where
  runtimeSessionId : Id := ""
  credentialKeyId : Option Id := none
  controlEpoch : Nat := 1
  roleId : Id := ""
  roleTenureId : Id := ""
  intentId : Option Id := none
  nonce : Option Id := none
  /-- Boundary fact: signature is present and structurally valid. -/
  signaturePresent : Bool := false
  /-- Boundary fact: verifies under the selected credential on the exact challenge. -/
  signatureVerified : Bool := false
  deriving BEq, Repr, Inhabited
structure Intent where
  intentId : Id := ""
  nonce : Id := ""
  actorId : Id := ""
  action : Id := ""
  resource : Id := ""
  roleId : Id := ""
  roleTenureId : Id := ""
  amount : Option Nat := none
  counterpartyId : Option Id := none
  termsCommitment : Option Id := none
  metric : Id := "amount"
  deriving BEq, Repr, Inhabited
structure NonceReservation where
  actorId : Id := ""
  nonce : Id := ""
  intentId : Id := ""
  /-- Distinguishes r4 declaration reservation from already admitted nonces. -/
  admitted : Bool := false
  deriving BEq, Repr, Inhabited
structure Counterparty where
  id : Id := ""
  retired : Bool := false
  deriving BEq, Repr, Inhabited
structure State where
  corpus : Corpus := {}
  head : Head := {}
  domain : Domain := {}
  policyVersion : Id := "policy"
  rootRecognitionPolicy : Id := "declared-principal-root/0.2"
  sessions : List Session := []
  roles : List Role := []
  tenures : List Tenure := []
  intents : List Intent := []
  admissions : List Id := []
  nonces : List NonceReservation := []
  /-- r4 §7.2 format-2 uncapped ledger, distinct from corpus.usage. -/
  format2Usage : List Usage := []
  /-- Read by receipt policy, not by inherited authority evaluation. -/
  counterparties : List Counterparty := []
  /-- Legacy0.2 alone permits absent expiry. Native format2 requires expiry;
      migrated-prefix shadow verification is outside this public-stage model. -/
  allowLegacyUnboundedSessions : Bool := false
  deriving BEq, Repr, Inhabited
structure Input where
  expectedHead : Head := {}
  domain : Domain := {}
  policyVersion : Id := "policy"
  rootRecognitionPolicy : Id := "declared-principal-root/0.2"
  request : Request := {}
  evaluationTime : Nat := 0
  consequential : Bool := false
  binding : Option Binding := none
  deriving BEq, Repr, Inhabited

def sameDomain (a b : Domain) : Bool := a.protocol == b.protocol && a.version == b.version &&
  a.deploymentId == b.deploymentId && a.chainId == b.chainId &&
  a.verifyingContract.toLower == b.verifyingContract.toLower

def sameIntent (d : Intent) (r : Request) (b : Binding) : Bool :=
  some d.intentId == b.intentId && some d.nonce == b.nonce && d.actorId == r.actorId &&
  d.action == r.action && d.resource == r.resource && d.roleId == b.roleId &&
  d.roleTenureId == b.roleTenureId && d.amount == r.amount &&
  d.counterpartyId == r.counterpartyId && d.termsCommitment == r.termsCommitment

def tenureCurrent (s : State) (actor : Id) (b : Binding) : Bool :=
  match s.roles.find? (·.id == b.roleId), s.tenures.find? (·.id == b.roleTenureId) with
  | some role, some tenure => role.currentTenureId == some b.roleTenureId && !tenure.closed &&
      tenure.roleId == b.roleId && tenure.agentId == actor
  | _, _ => false

def bindingProblem (s : State) (r : Request) (t : Nat) (a : Agent) (b : Binding) : Option (Code × Id) :=
  match s.sessions.find? (·.id == b.runtimeSessionId) with
  | none => some (.SESSION_NOT_FOUND, b.runtimeSessionId)
  | some session =>
    if session.agentId != a.id then some (.SESSION_NOT_FOUND, b.runtimeSessionId)
    else if session.expiresAt.any (t >= ·) || (session.expiresAt.isNone && !s.allowLegacyUnboundedSessions) then some (.SESSION_EXPIRED, b.runtimeSessionId)
    else if b.credentialKeyId.isNone || !b.signaturePresent then some (.SESSION_CREDENTIAL_REQUIRED, b.runtimeSessionId)
    else if b.credentialKeyId != some session.credentialKeyId then some (.SESSION_CREDENTIAL_INVALID, b.runtimeSessionId)
    else if b.intentId.isSome && b.nonce.isSome && !b.signatureVerified then some (.SESSION_CREDENTIAL_INVALID, b.runtimeSessionId)
    else if session.controlEpoch < a.currentControlEpoch then some (.SESSION_FENCED, b.runtimeSessionId)
    else if b.controlEpoch != session.controlEpoch || b.controlEpoch != a.currentControlEpoch then some (.STALE_EPOCH, b.runtimeSessionId)
    else if !tenureCurrent s a.id b then some (.ROLE_TENURE_NOT_CURRENT, b.roleTenureId)
    else match b.intentId, b.nonce with
      | some id, some _ => match s.intents.find? (·.intentId == id) with
        | none => some (.INTENT_NOT_DECLARED, id)
        | some declaration =>
          if !sameIntent declaration r b then some (.INTENT_MISMATCH, id)
          else if s.admissions.contains id then some (.INTENT_REPLAY, id) else none
      | _, _ => some (.INTENT_REQUIRED, a.id)

def nonceAlreadyAdmitted (s : State) (i : Input) : Option Id :=
  if !i.consequential then none else do
    let b ← i.binding
    let nonce ← b.nonce
    if s.nonces.any (fun n => n.actorId == i.request.actorId && n.nonce == nonce && n.admitted)
      then some nonce else none

def stageAfterCorpus (s : State) (i : Input) (paths : List Path) : Decision :=
  match (s.corpus.agents.getD []).find? (·.id == i.request.actorId) with
  | none => deny .AGENT_INACTIVE (some i.request.actorId)
  | some actor =>
    if actor.terminated then deny .AGENT_INACTIVE (some i.request.actorId)
    else
      let bindingError := if i.consequential then i.binding.bind (bindingProblem s i.request i.evaluationTime actor) else none
      match bindingError with
      | some (code, subject) => deny code (some subject)
      | none => match evaluateAlgebra s.corpus paths i.request i.evaluationTime (format2Usage := s.format2Usage) with
        | .allow candidate => match nonceAlreadyAdmitted s i with
          | some nonce => deny .NONCE_ALREADY_ADMITTED (some nonce)
          | none => finalize s.corpus (.allow candidate)
        | other => other

def authorizeState (s : State) (i : Input) : Decision :=
  if i.expectedHead != s.head then .indeterminate .HISTORY_RELATION_UNVERIFIED
  else if i.evaluationTime > maxU53 || i.evaluationTime < s.head.canonicalTime then .indeterminate .CAUSAL_TIME_INVALID
  else if !sameDomain i.domain s.domain then deny .DOMAIN_MISMATCH
  else if i.policyVersion != s.policyVersion || i.rootRecognitionPolicy != s.rootRecognitionPolicy then deny .POLICY_MISMATCH
  else match requestProblem i.request with
    | some code => deny code
    | none => match validateCorpus s.corpus with
      | .error .INVALID_INPUT => .indeterminate .STATE_NOT_AUTHORITATIVE
      | .error _ => deny .INVALID_DELEGATION
      | .ok paths => stageAfterCorpus s i paths

/-- Explicit façade boundary: no claims about JS object capture, replay or crypto
    implementations are made by assuming these facts. Unknown version precedes
    body validity; structural body validity precedes replay rejection. -/
structure Boundary where
  operationVersionPresent : Bool := true
  operationVersionValidString : Bool := true
  operationVersionSupported : Bool := true
  bodyStructural : Bool := true
  replayFailure : Option Code := none
  deriving BEq, Repr, Inhabited

def authorize (boundary : Boundary) (s : State) (i : Input) : Decision :=
  if !boundary.operationVersionPresent || !boundary.operationVersionValidString then .indeterminate .INVALID_INPUT
  else if !boundary.operationVersionSupported then .indeterminate .UNSUPPORTED_VERSION
  else if !boundary.bodyStructural || requestCaptureLimit i.request || i.consequential != i.binding.isSome then .indeterminate .INVALID_INPUT
  else match boundary.replayFailure with
    | some .UNSUPPORTED_VERSION => .indeterminate .UNSUPPORTED_VERSION
    | some _ => .indeterminate .STATE_NOT_AUTHORITATIVE
    | none => authorizeState s i

/-- §8.1 budget denial wrapper, independent of budget recurrence. -/
def withBudget (budgetFailure : Option Code) : Decision → Decision
  | .allow c => match budgetFailure with | none => .allow c | some code => deny code
  | result => result

/-- Legacy capped ledger only: each controlling id is charged once, and only
    capped dimensions move. The caller commits the returned list atomically. -/
def nextCappedUsage (c : Corpus) (candidate : Candidate) (request : Request) : Option (List Usage) :=
  candidate.graph.controlling.filterMap (fun id =>
    (permission c id).filter (fun p => p.constraints.maxTransactions.isSome || p.constraints.maxCumulativeAmount.isSome)) |>.mapM fun p => do
      let u ← usageFor c p.authorityId
      let amount ← if p.constraints.maxCumulativeAmount.isSome then request.amount else some 0
      let count := u.admittedTransactionCount + if p.constraints.maxTransactions.isSome then 1 else 0
      let total := u.admittedCumulativeAmount + amount
      if count > maxU53 || total > maxAmount ||
          p.constraints.maxTransactions.any (count > ·) || p.constraints.maxCumulativeAmount.any (total > ·)
        then none else some { authorityId := p.authorityId, admittedTransactionCount := count, admittedCumulativeAmount := total }

/-- Authority eligibility is unaffected by role succession except where a
    consequential request names the old tenure. No permission is transferred. -/
def closeTenure (s : State) (tenureId : Id) : State :=
  { s with tenures := s.tenures.map fun t => if t.id == tenureId then { t with closed := true } else t }

def terminateAgent (s : State) (actor : Id) : State :=
  { s with corpus := { s.corpus with agents := s.corpus.agents.map (fun agents =>
    agents.map fun a => if a.id == actor then { a with terminated := true } else a) } }

def revokePermission (c : Corpus) (id : Id) : Corpus :=
  { c with revoked := union (id :: c.revoked) }

end Authority
