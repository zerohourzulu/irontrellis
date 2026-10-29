import Std

/- Independent A-114/A-124 model, from packet text only.
   Credentials are normalized atoms; digest is injective by construction.
   Signatures carry an ideal, injective challenge witness, not Ed25519.
   Typed bodies abstract closed schemas and non-G6 r4 preconditions.
   Optional fields preserve absence. Maps use unique sorted entries.
-/
namespace IronTrellis

def MAXT : Nat := 9007199254740991
abbrev Cred := Nat
structure Key where
  id : Nat
  cred : Cred
  valid : Bool := true
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

def digest (k : Key) : Cred := k.cred

def sameSet [BEq α] (xs ys : List α) : Bool :=
  xs.all (ys.contains ·) && ys.all (xs.contains ·)

def unique [BEq α] : List α → Bool
  | [] => true
  | x :: xs => !xs.contains x && unique xs

inductive Tag where
  | revoke | fence | terminate | unappoint | appoint | budgetDeclare | budgetUpdate
  | retire | checkpoint | rotate | grant | agentDeclare | sessionAdmit
  | counterpartyRegister | budgetClose | witnessesUnbind | anchor | ordinary
  | session | administrative | roleCreate | successionRule | roleTransfer | witnessesBind
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

def Tag.control : Tag → Bool
  | .session | .administrative => false
  | _ => true

def Tag.prType : Tag → Bool
  | .revoke | .fence | .terminate | .unappoint | .budgetDeclare | .budgetUpdate | .retire => true
  | _ => false

def Tag.lowType (t : Tag) : Bool := t.prType || t == .checkpoint

inductive Class where
  | human | agent | lapsed | none
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

def Class.humanClass : Class → Bool
  | .human | .lapsed => true
  | _ => false

def Class.rank : Class → Nat
  | .none => 0 | .lapsed => 1 | .human => 2 | .agent => 3

structure Attestation where
  subject : Key
  attesterId : Nat
  audience : Nat
  profile : Nat := 0
  evidence : Nat := 0
  notBefore : Nat
  expiresAt : Nat
  historyId : Option Nat := none
  signed : Bool := true
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

structure Policy where
  threshold : Nat := 1
  byType : Option (List (Tag × Nat)) := none
  keyClasses : Option (List (Nat × Class)) := none
  labels : Option (List (Nat × Nat)) := none
  acknowledged : Bool := false
  humanFloor : Option Bool := none -- some true ATTESTED; some false DECLARED
  attesters : Option (List Key) := none
  attestations : Option (List Attestation) := none
  recovery : Bool := false
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

def tagCode : Tag → Nat
  | .revoke => 11 | .fence => 9 | .terminate => 20 | .unappoint => 6 | .appoint => 5
  | .budgetDeclare => 32 | .budgetUpdate => 33 | .retire => 37
  | .checkpoint => 35 | .rotate => 26 | .grant => 10 | .agentDeclare => 2
  | .sessionAdmit => 8 | .counterpartyRegister => 36 | .budgetClose => 34
  | .witnessesUnbind => 28 | .anchor => 25 | .ordinary => 1
  | .session => 12 | .administrative => 17
  | .roleCreate => 3 | .successionRule => 4 | .roleTransfer => 7 | .witnessesBind => 27

def insertBy (le : α → α → Bool) (x : α) : List α → List α
  | [] => [x]
  | y :: ys => if le x y then x :: y :: ys else y :: insertBy le x ys

def sortBy (le : α → α → Bool) : List α → List α
  | [] => []
  | x :: xs => insertBy le x (sortBy le xs)

def canonicalPolicy (p : Policy) : Policy :=
  {p with
    byType := p.byType.map (fun xs => sortBy (fun a b => tagCode a.1 ≤ tagCode b.1) xs)
    keyClasses := p.keyClasses.map (fun xs => sortBy (fun a b => a.1 ≤ b.1) xs)
    labels := p.labels.map (fun xs => sortBy (fun a b => a.1 ≤ b.1) xs)}

def Policy.att (p : Policy) : Bool := p.humanFloor == some true

def Policy.override (p : Policy) (t : Tag) : Option Nat :=
  ((p.byType.getD []).find? (fun q => q.1 == t)).map Prod.snd

def Policy.mrot (p : Policy) : Nat := (p.override .rotate).getD p.threshold

def Policy.stmt (p : Policy) (c : Cred) : Option Attestation :=
  (p.attestations.getD []).find? (fun a => a.subject.cred == c)

def Policy.agentCred (p : Policy) (ks : List Key) (c : Cred) : Bool :=
  ks.any fun k => k.cred == c &&
    (p.keyClasses.getD []).any (fun q => q.1 == k.id && q.2 == .agent)

def validAt (a : Attestation) (t : Nat) : Bool := a.notBefore ≤ t && t < a.expiresAt

def Policy.started (p : Policy) (c : Cred) (t : Nat) : Bool :=
  match p.stmt c with | none => false | some a => a.notBefore ≤ t

def Policy.validAt (p : Policy) (c : Cred) (t : Nat) : Bool :=
  match p.stmt c with | none => false | some a => IronTrellis.validAt a t

def cls (p : Policy) (ks : List Key) (t : Nat) (c : Cred) : Class :=
  if !p.att then if p.agentCred ks c then .agent else .human
  else if p.validAt c t then .human
  else if p.agentCred ks c then .agent
  else match p.stmt c with
    | some a => if a.expiresAt ≤ t then .lapsed else .none
    | none => .none

def Policy.horizon (p : Policy) : Nat :=
  (p.attestations.getD []).foldl (fun n a => max n a.expiresAt) 0

def Policy.subjects (p : Policy) : List Cred := (p.attestations.getD []).map (·.subject.cred)
def Policy.attCreds (p : Policy) : List Cred := (p.attesters.getD []).map (·.cred)

def policyCore (p : Policy) : Policy := canonicalPolicy {p with attestations := none, labels := none}

structure Agent where
  id : Nat
  active : Bool := true
  epoch : Nat := 0
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr
structure Authority where
  id : Nat
  permission : Bool := true
  revoked : Bool := false
  parent : Option Nat := none
  grantor : Nat := 0
  grantee : Nat := 0
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr
structure Session where
  id : Nat
  cred : Cred
  agent : Nat
  epoch : Nat
  expiresAt : Nat
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr
structure Counterparty where
  id : Nat
  active : Bool := true
  keys : List Cred
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr
structure Subjects where
  actors : Option (List Nat) := none
  roles : Option (List Nat) := none
  actions : Option (List Nat) := none
  resources : Option (List Nat) := none
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr
inductive Period where
  | none | fixed (start width : Nat) (carryUnused : Bool)
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr
structure Budget where
  id : Nat
  active : Bool := true
  amountCap : Option Nat := none
  countCap : Option Nat := none
  perOperationCap : Option Nat := none
  subjects : Subjects := {}
  expiresAt : Option Nat := none
  period : Period := .none
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

def Budget.rolls (b : Budget) : Bool :=
  match b.period with | .fixed _ _ carry => carry | _ => false

structure Records where
  authorities : List Authority := []
  agents : List Agent := []
  sessions : List Session := []
  counterparties : List Counterparty := []
  budgets : List Budget := []
  tenures : List (Nat × Nat) := [] -- active (agent,role) pairs
  witnesses : List Nat := []
  witnessPolicy : Nat := 0
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

def Records.foreign (r : Records) : List Cred :=
  r.sessions.map (·.cred) ++ r.counterparties.flatMap (·.keys)

structure Epoch where
  keys : List Key
  digests : Option (List Cred) := none
  policy : Option Policy := none
  tset : Nat
  fromPosition : Nat := 0
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

def Epoch.p (ep : Epoch) : Policy := ep.policy.getD {}

def Epoch.d (ep : Epoch) : List Cred := ep.digests.getD []

structure State where
  epoch : Epoch
  records : Records := {}
  historicalKeys : List Key
  time : Nat
  position : Nat := 1 -- next position
  head : Nat := 1 -- abstract authenticated head identity
  historyId : Nat := 1
  domain : Nat := 1
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

/- Bodies are algebraic effect structures. Signature fields are separate and
   hence exactly the four specified fields are excluded from this abstraction. -/
structure Body where
  tag : Tag
  ownerKeys : List Key := []
  policy : Option Policy := none
  digests : Option (List Cred) := none
  target : Nat := 0
  role : Nat := 0
  fromEpoch : Nat := 0
  toEpoch : Nat := 0
  authority : Authority := {id := 0}
  agent : Agent := ⟨0, true, 0⟩
  session : Session := ⟨0, 0, 0, 0, 0⟩
  counterparty : Counterparty := ⟨0, true, []⟩
  budget : Budget := ⟨0, true, none, none, none, {}, none, .none⟩
  payload : Nat := 0
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr
structure Challenge where
  domain : Nat
  previousHead : Nat
  eventId : Nat
  timestamp : Nat
  effect : Body
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr
structure Signature where
  keyId : Nat
  credential : Cred
  challenge : Challenge
  valid : Bool := true
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr
structure Event where
  id : Nat
  time : Nat
  body : Body
  control : Option Signature := none
  additional : Option (List Signature) := none
  next : Option (List Signature) := none
  source : Option Signature := none
  inPrefix : Bool := false
  capacityOK : Bool := true -- §5.2 external precondition, made explicit
  basePrecondition : Bool := true -- other r4 per-type preconditions, explicit
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

def challenge (s : State) (e : Event) : Challenge := ⟨s.domain, s.head, e.id, e.time, e.body⟩
def signers (e : Event) : List Signature := e.control.toList ++ e.additional.getD []
def revealed (s : State) (e : Event) : List Key :=
  e.body.ownerKeys.filter (fun k => !(s.epoch.keys.map (·.id)).contains k.id)
def guard (s : State) (e : Event) : Bool := s.epoch.policy.isSome || e.body.policy.isSome

def keepsEveryKey (s : State) (e : Event) : Bool :=
  e.body.ownerKeys.length == s.epoch.keys.length &&
    e.body.ownerKeys.all (s.epoch.keys.contains ·)
def isPolicyRot (s : State) (e : Event) : Bool :=
  e.body.tag == .rotate && keepsEveryKey s e && (e.body.policy.map canonicalPolicy) != (s.epoch.policy.map canonicalPolicy)

def renewal (a' a : Attestation) (tset t : Nat) : Bool :=
  a'.subject.cred == a.subject.cred && max a.notBefore tset < a'.notBefore &&
    a'.notBefore ≤ t && a.expiresAt < a'.expiresAt

def isRestoration (s : State) (e : Event) : Bool :=
  isPolicyRot s e && s.epoch.p.att &&
  match e.body.policy with
  | none => false
  | some p => p.att && policyCore p == policyCore s.epoch.p &&
    e.body.digests.isSome == s.epoch.digests.isSome &&
    sameSet (e.body.digests.getD []) s.epoch.d &&
    sameSet p.subjects s.epoch.p.subjects &&
    (p.attestations.getD []).all (fun a' =>
      (s.epoch.p.attestations.getD []).contains a' ||
      match s.epoch.p.stmt a'.subject.cred with
      | none => false
      | some a => renewal a' a s.epoch.tset e.time)

def isRecovery (s : State) (e : Event) : Bool :=
  e.body.tag == .rotate && s.epoch.p.recovery &&
    (signers e).any (fun sig => (revealed s e).any
      (fun k => k.id == sig.keyId && s.epoch.d.contains (digest k)))

def adm (s : State) (e : Event) : List Key :=
  s.epoch.keys ++ if e.body.tag == .rotate && s.epoch.p.recovery then
    (revealed s e).filter (fun k => s.epoch.d.contains (digest k)) else []

def resolve (s : State) (e : Event) (sig : Signature) : Option Key :=
  (adm s e).find? (fun k => k.id == sig.keyId)

def verifies (s : State) (e : Event) (sig : Signature) : Bool :=
  match resolve s e sig with
  | none => false
  | some k => k.valid && sig.valid && sig.credential == k.cred && sig.challenge == challenge s e

def ancestorFuel (r : Records) (fuel target : Nat) (a : Authority) : Bool :=
  match fuel with
  | 0 => false
  | n+1 => match a.parent with
    | none => false
    | some pid => pid == target ||
      match r.authorities.find? (fun b => b.id == pid) with
      | none => false
      | some b => ancestorFuel r n target b

def capTightens (old new : Option Nat) : Bool :=
  match old, new with
  | none, _ => true | some _, none => false | some o, some n => n ≤ o

def selectionWidens (old new : Option (List Nat)) : Bool :=
  match old, new with
  | _, none => true | none, some _ => false | some o, some n => o.all (n.contains ·)

def expiryExtends (old new : Option Nat) : Bool :=
  match old, new with
  | _, none => true | none, some _ => false | some o, some n => o ≤ n

def budgetTightens (old new : Budget) : Bool :=
  capTightens old.amountCap new.amountCap && capTightens old.countCap new.countCap &&
  capTightens old.perOperationCap new.perOperationCap &&
  selectionWidens old.subjects.actors new.subjects.actors &&
  selectionWidens old.subjects.roles new.subjects.roles &&
  selectionWidens old.subjects.actions new.subjects.actions &&
  selectionWidens old.subjects.resources new.subjects.resources &&
  expiryExtends old.expiresAt new.expiresAt

/-- A-127.2/A-203: parent-path mentions, without any activity/window filter.
    This is the record-walk form of Authority.G64.prohibitionMentions. -/
def terminationMentions (r : Records) (p : Authority) (id : Nat) : Bool :=
  p.grantor == id || r.authorities.any (fun a =>
    ancestorFuel r r.authorities.length a.id p && (a.grantor == id || a.grantee == id))

def prEff (r : Records) (b : Body) (t : Nat) : Bool :=
  match b.tag with
  | .revoke => match r.authorities.find? (fun a => a.id == b.target) with
    | none => false
    | some a => !a.revoked && a.permission &&
      !r.authorities.any (fun p => !p.revoked && !p.permission &&
        ancestorFuel r r.authorities.length a.id p)
  | .fence => (r.agents.any (fun a => a.id == b.target && a.active && a.epoch == b.fromEpoch)) &&
    b.fromEpoch < b.toEpoch && !r.sessions.any (fun ss => ss.agent == b.target && ss.epoch == b.toEpoch)
  | .terminate => r.agents.any (fun a => a.id == b.target && a.active) &&
    !r.authorities.any (fun a => !a.revoked && !a.permission && terminationMentions r a b.target)
  | .unappoint => !r.budgets.any (fun budget => budget.active &&
    (budget.subjects.roles.getD []).contains b.role &&
    (budget.subjects.actors.isNone || (budget.subjects.actors.getD []).contains b.target) &&
    !(budget.expiresAt.any (· ≤ t)))
  | .budgetDeclare => true
  | .budgetUpdate => match r.budgets.find? (fun budget => budget.id == b.budget.id) with
    | none => false
    | some old => old.active && !old.rolls && budgetTightens old b.budget
  | .retire => r.counterparties.any (fun cp => cp.id == b.target && cp.active)
  | _ => false

def meff (s : State) (e : Event) : Nat :=
  let p := s.epoch.p
  let m := (p.override e.body.tag).getD p.threshold
  if e.body.tag.prType && m < p.threshold && !(prEff s.records e.body e.time)
  then p.threshold else m

def exempt (s : State) (e : Event) : Bool :=
  prEff s.records e.body e.time || isRestoration s e || e.body.tag == .checkpoint

def signerClass (s : State) (e : Event) (sig : Signature) : Class :=
  cls s.epoch.p s.epoch.keys e.time sig.credential

def counts (att : Bool) (rotate rest exempt : Bool) (c : Class) : Bool :=
  if !att then if rotate then c != .agent else true
  else if rotate then if rest then c.humanClass else c == .human
  else if exempt then c != .none else c == .human || c == .agent

def counting (s : State) (e : Event) : List Signature :=
  (signers e).filter (fun sig => counts s.epoch.p.att (e.body.tag == .rotate)
    (isRestoration s e) (exempt s e) (signerClass s e sig))

def hc (s : State) (e : Event) : Nat :=
  ((counting s e).filter (fun sig => (signerClass s e sig).humanClass)).length

def authorization (s : State) (e : Event) : Bool :=
  e.control.isSome && (signers e).all (verifies s e) &&
  (e.additional.isSome == (meff s e ≥ 2)) &&
  unique ((signers e).map (·.keyId)) && unique ((signers e).map (·.credential)) &&
  meff s e ≤ (counting s e).length &&
  (counting s e).any (fun sig => (signerClass s e sig).humanClass)

def t1 (s : State) (e : Event) : Bool :=
  !s.epoch.p.att || e.body.tag.control ||
    (s.epoch.p.attestations.getD []).all (fun a => a.expiresAt ≤ s.time || e.time < a.expiresAt)

def t2 (s : State) (e : Event) : Bool :=
  !s.epoch.p.att || !(e.body.tag.control) || hc s e > 1 ||
    e.time == s.time || e.time ≤ min s.epoch.p.horizon (MAXT-1)

/- Schema and policy checks are separate from authorization; no desired safety
   theorem is assumed. All policy-time bounds are the normative validation rules. -/
def optionalListShape (xs : Option (List α)) (limit : Nat) : Bool :=
  match xs with | none => true | some xs => !xs.isEmpty && xs.length ≤ limit

def policyShape (p : Policy) : Bool :=
  1 ≤ p.threshold && p.threshold ≤ 64 && (p.byType.getD []).all (fun q => 1 ≤ q.2 && q.2 ≤ 64) &&
  optionalListShape p.byType 22 && optionalListShape p.keyClasses 64 &&
  optionalListShape p.labels 64 && optionalListShape p.attesters 16 &&
  optionalListShape p.attestations 64 && unique ((p.keyClasses.getD []).map Prod.fst) &&
  unique ((p.labels.getD []).map Prod.fst) &&
  unique ((p.byType.getD []).map Prod.fst) &&
  (p.byType.getD []).all (fun q => q.1.control) &&
  (p.keyClasses.getD []).all (fun q => q.2 == .human || q.2 == .agent) &&
  (p.attestations.getD []).all (fun a => a.notBefore ≤ MAXT && a.expiresAt ≤ MAXT)

def keyShape (ks : List Key) : Bool :=
  !ks.isEmpty && ks.length ≤ 64 && unique (ks.map (·.id)) && ks.all (·.valid)

def digestShape (ds : Option (List Cred)) : Bool :=
  match ds with | none => true | some ds => !ds.isEmpty && ds.length ≤ 64 && unique ds

def policyValid (s : State) (ks : List Key) (ds : List Cred) (p : Policy)
    (t : Nat) (genesis : Bool := false) : Bool :=
  let nonAgents := ks.filter (fun k => !(p.agentCred ks k.cred))
  let valid := ks.filter (fun k => p.validAt k.cred t)
  let started := ks.filter (fun k => p.started k.cred t)
  policyShape p && 1 ≤ p.threshold && p.threshold ≤ 64 && p.threshold ≤ ks.length &&
  unique (ks.map (·.cred)) &&
  (p.byType.getD []).all (fun q => q.1.control && 1 ≤ q.2 && q.2 ≤ ks.length &&
    (q.1 != .rotate || p.threshold ≤ q.2) &&
    (p.threshold ≤ q.2 || q.1.lowType) &&
    (!q.1.prType || q.2 ≤ nonAgents.length) &&
    (!p.att || !q.1.prType || q.2 ≤ started.length)) &&
  unique ((p.byType.getD []).map Prod.fst) &&
  p.mrot ≤ nonAgents.length &&
  (p.keyClasses.getD []).all (fun q => (ks.map (·.id)).contains q.1 && (q.2 == .human || q.2 == .agent)) &&
  (p.labels.getD []).all (fun q => (ks.map (·.id)).contains q.1) &&
  (!p.acknowledged || (p.threshold == 1 && p.byType.isNone)) &&
  (p.attestations.isNone || p.attesters.isSome) &&
  (!p.att || (p.attesters.isSome && p.attestations.isSome &&
    2 ≤ (p.attesters.getD []).length && p.mrot ≤ valid.length)) &&
  unique ((p.attesters.getD []).map (·.id)) && unique p.attCreds &&
  (p.attesters.getD []).all (fun a => a.valid &&
    !(ks.map (·.cred)).contains a.cred && !ds.contains a.cred &&
    !(s.records.foreign.contains a.cred)) &&
  unique p.subjects &&
  (p.attestations.getD []).all (fun a =>
    a.audience == s.domain && a.signed &&
    (p.attesters.getD []).any (fun att => att.id == a.attesterId) &&
    (ks.contains a.subject || ds.contains a.subject.cred) &&
    a.notBefore < a.expiresAt && a.expiresAt ≤ MAXT &&
    (t < a.expiresAt || (!genesis && (s.epoch.p.attestations.getD []).contains a)) &&
    !(p.agentCred ks a.subject.cred) &&
    (if genesis then a.historyId.isNone else
      (s.epoch.p.attestations.getD []).contains a || a.historyId == some s.historyId))

def resultingPolicyValid (s : State) (e : Event) : Bool :=
  match e.body.policy with
  | none => true
  | some p => policyValid s e.body.ownerKeys (e.body.digests.getD []) p e.time

def keyHistoryOK (s : State) (e : Event) : Bool :=
  e.body.ownerKeys.all (fun k =>
    match s.historicalKeys.find? (fun old => old.id == k.id) with
    | some old => old == k && s.epoch.keys.contains k
    | none => !(s.historicalKeys.map (·.cred)).contains k.cred)

def introduced (s : State) (e : Event) : List Cred :=
  (e.body.digests.getD []).filter (fun d => !s.epoch.d.contains d)

def foreignOwnerOK (s : State) (e : Event) : Bool :=
  !guard s e || e.body.ownerKeys.all (fun k => !s.records.foreign.contains k.cred)
def foreignDigestOK (s : State) (e : Event) : Bool :=
  !guard s e || (introduced s e).all (fun d =>
    !(s.records.foreign ++ s.epoch.p.attCreds ++ (e.body.policy.getD {}).attCreds).contains d)

def nextVerifies (s : State) (e : Event) (sig : Signature) : Bool :=
  (revealed s e).any (fun k => k.id == sig.keyId && k.valid && sig.valid &&
    k.cred == sig.credential && sig.challenge == challenge s e)

def commitmentOK (s : State) (e : Event) : Bool :=
  (e.next.getD []).all (nextVerifies s e) &&
  unique ((e.next.getD []).map (·.keyId)) &&
  (e.body.digests.getD []).all (fun d =>
    !(s.historicalKeys ++ e.body.ownerKeys).any (fun k => digest k == d)) &&
  if s.epoch.digests.isSome then
    if isPolicyRot s e then e.next.isNone && e.body.digests.isSome &&
      sameSet (e.body.digests.getD []) s.epoch.d
    else !(revealed s e).isEmpty &&
      (revealed s e).all (fun k => s.epoch.d.contains (digest k)) &&
      e.next.isSome && e.body.digests.isSome &&
      (!guard s e || (revealed s e).all (fun k =>
        ((e.next.getD []).filter (fun sig => sig.keyId == k.id)).length == 1))
  else !keepsEveryKey s e || e.body.digests.isSome || isPolicyRot s e

def registrationOK (s : State) (e : Event) : Bool :=
  if s.epoch.policy.isNone then true else
  let bad := s.epoch.keys.map (·.cred) ++ s.epoch.d ++ s.epoch.p.attCreds
  match e.body.tag with
  | .sessionAdmit => !bad.contains e.body.session.cred
  | .counterpartyRegister => e.body.counterparty.keys.all (fun c => !bad.contains c)
  | _ => true

def transitionOK (s : State) (e : Event) : Bool :=
  e.basePrecondition && registrationOK s e &&
  match e.body.tag with
  | .rotate => keyHistoryOK s e && commitmentOK s e && foreignDigestOK s e
  | .revoke => s.records.authorities.any (fun a => a.id == e.body.target && !a.revoked)
  | .fence => s.records.agents.any (fun a => a.id == e.body.target && a.active && a.epoch == e.body.fromEpoch) &&
      e.body.fromEpoch < e.body.toEpoch
  | .terminate => s.records.agents.any (fun a => a.id == e.body.target && a.active)
  | .appoint => !s.records.tenures.contains (e.body.target, e.body.role)
  | .unappoint => s.records.tenures.contains (e.body.target, e.body.role)
  | .budgetDeclare => !s.records.budgets.any (fun b => b.id == e.body.budget.id) && s.records.budgets.length < 256
  | .budgetUpdate => s.records.budgets.any (fun b => b.id == e.body.budget.id && b.active && e.body.budget.active && b.period == e.body.budget.period)
  | .retire => s.records.counterparties.any (fun cp => cp.id == e.body.target && cp.active)
  | .agentDeclare => !s.records.agents.any (fun a => a.id == e.body.agent.id)
  | .grant => !s.records.authorities.any (fun a => a.id == e.body.authority.id)
  | .sessionAdmit => !s.records.sessions.any (fun ss => ss.id == e.body.session.id)
  | _ => true

inductive Code where
  | eventDataInvalid | controlAuthorizationInvalid | transitionInvalid
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr
abbrev Gate := Code × Bool

def eventSchema (e : Event) : Bool :=
  (if e.body.tag == .rotate then
     !e.body.ownerKeys.isEmpty && e.body.ownerKeys.length ≤ 64 && unique (e.body.ownerKeys.map (·.id)) && digestShape e.body.digests
   else e.body.ownerKeys.isEmpty && e.body.policy.isNone && e.body.digests.isNone && e.next.isNone) &&
  (e.body.tag.control || (e.control.isNone && e.additional.isNone)) &&
  (e.inPrefix || e.source.isNone)

def checks (s : State) (e : Event) : List Gate :=
  [(.eventDataInvalid, eventSchema e && (e.body.policy.all policyShape) && optionalListShape e.additional 63 && optionalListShape e.next 64 && e.time ≤ MAXT && (!e.inPrefix || (e.body.policy.isNone && e.additional.isNone && e.body.tag != .rotate))),
   (.transitionInvalid, s.time ≤ e.time),
   (.transitionInvalid, t1 s e)] ++
  (if e.body.tag.control then
    [(.controlAuthorizationInvalid, authorization s e), (.transitionInvalid, t2 s e)] else []) ++
  (if e.body.tag == .rotate then
    [(.eventDataInvalid, keyShape e.body.ownerKeys && digestShape e.body.digests && foreignOwnerOK s e),
     (.eventDataInvalid, resultingPolicyValid s e)] else []) ++
  [(.transitionInvalid, transitionOK s e), (.transitionInvalid, e.capacityOK)]

def firstFailure : List Gate → Option Code
  | [] => none
  | (code, ok) :: rest => if ok then firstFailure rest else some code

def verdict (s : State) (e : Event) : Option Code := firstFailure (checks s e)
def Accepted (s : State) (e : Event) : Prop := verdict s e = none

instance (s : State) (e : Event) : Decidable (Accepted s e) := inferInstanceAs (Decidable (verdict s e = none))

def apply (s : State) (e : Event) : State :=
  let r := s.records
  let r' := match e.body.tag with
    | .revoke => { r with authorities := r.authorities.map (fun a => if a.id == e.body.target then {a with revoked := true} else a) }
    | .fence => {r with agents := r.agents.map (fun a => if a.id == e.body.target then {a with epoch := e.body.toEpoch} else a)}
    | .terminate => {r with agents := r.agents.map (fun a => if a.id == e.body.target then {a with active := false} else a)}
    | .appoint => {r with tenures := r.tenures ++ [(e.body.target,e.body.role)]}
    | .unappoint => {r with tenures := r.tenures.filter (· != (e.body.target,e.body.role))}
    | .budgetDeclare => {r with budgets := r.budgets ++ [e.body.budget]}
    | .budgetUpdate => {r with budgets := r.budgets.map (fun b => if b.id == e.body.budget.id then e.body.budget else b)}
    | .retire => {r with counterparties := r.counterparties.map (fun cp => if cp.id == e.body.target then {cp with active := false} else cp)}
    | .agentDeclare => {r with agents := r.agents ++ [e.body.agent]}
    | .grant => {r with authorities := r.authorities ++ [e.body.authority]}
    | .sessionAdmit => {r with sessions := r.sessions ++ [e.body.session]}
    | .counterpartyRegister => {r with counterparties := r.counterparties.filter (fun cp => cp.id != e.body.counterparty.id) ++ [e.body.counterparty]}
    | _ => r
  {s with
    records := r'
    time := e.time
    position := s.position + 1
    head := s.head + 1
    epoch := if e.body.tag == .rotate then
      ⟨e.body.ownerKeys, e.body.digests, e.body.policy, e.time, s.position+1⟩ else s.epoch
    
    historicalKeys := (if e.body.tag == .rotate then s.historicalKeys ++ revealed s e else s.historicalKeys)}

structure Genesis where
  keys : List Key
  digests : Option (List Cred) := none
  policy : Option Policy := none
  time : Nat := 0
  domain : Nat := 1
  historyId : Nat := 1
  migrated : Bool := false
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

def initialState (g : Genesis) : State :=
  {epoch := ⟨g.keys,g.digests,g.policy,g.time,0⟩, historicalKeys := g.keys,
    time := g.time, domain := g.domain, historyId := g.historyId}

def genesisValid (g : Genesis) : Bool :=
  keyShape g.keys && digestShape g.digests && g.time ≤ MAXT &&
  (!g.migrated || g.policy.isNone) &&
  (g.digests.getD []).all (fun d => !(g.keys.map (·.cred)).contains d) &&
  match g.policy with
  | none => true
  | some p => policyValid (initialState g) g.keys (g.digests.getD []) p g.time true

inductive Reachable : State → Prop where
  | genesis (g : Genesis) (valid : genesisValid g = true) : Reachable (initialState g)
  | step {s : State} {e : Event} (history : Reachable s) (accepted : Accepted s e) : Reachable (apply s e)

def replay (s : State) : List Event → Option State
  | [] => some s
  | e :: es => if Accepted s e then replay (apply s e) es else none

/- This state-free subset deletes only the named foreign rules. The in-force
   attester digest check is also removed exactly as A-120.1 instructs. -/
def sfState (s : State) : State := {s with records := {}}
def sfChecks (s : State) (e : Event) : List Gate :=
  [(.eventDataInvalid, eventSchema e && (e.body.policy.all policyShape) && optionalListShape e.additional 63 && optionalListShape e.next 64 && e.time ≤ MAXT && (!e.inPrefix || (e.body.policy.isNone && e.additional.isNone && e.body.tag != .rotate))),
   (.transitionInvalid, s.time ≤ e.time),
   (.controlAuthorizationInvalid, authorization s e), (.transitionInvalid, t2 s e),
   (.eventDataInvalid, keyShape e.body.ownerKeys && digestShape e.body.digests),
   (.eventDataInvalid, resultingPolicyValid (sfState s) e),
   (.transitionInvalid, e.basePrecondition && keyHistoryOK s e && commitmentOK s e &&
     (introduced s e).all (fun d => !((e.body.policy.getD {}).attCreds.contains d))),
   (.transitionInvalid, e.capacityOK)]
def acceptSF (s : State) (e : Event) : Prop := firstFailure (sfChecks s e) = none

end IronTrellis
