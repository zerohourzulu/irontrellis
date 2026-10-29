import Std

namespace Anchor

/-- Digests are opaque values; no concrete hash implementation is asserted. -/
abbrev Digest := String

structure Domain where
  protocol : String
  version : String
  deploymentId : String
  chainId : String
  verifyingContract : String
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

structure Profile where
  id : String
  manifestHash : Digest
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

structure ChainDestination where
  id : String
  destination : String
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

structure Head where
  hash : Digest
  position : Nat
  canonicalTime : Nat
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

structure ShortHead where
  hash : Digest
  position : Nat
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

def Head.short (h : Head) : ShortHead := ⟨h.hash, h.position⟩

structure Evidence where
  manifestDigest : Option Digest
  certificateDigest : Option Digest
  checkpointEventId : Option String
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

/-- Every A-144 field is represented. Option values mean explicit null on the wire. -/
structure Statement where
  version : String
  domain : Domain
  historyId : Digest
  genesisEventHash : Digest
  profile : Profile
  head : Head
  stateRoot : Digest
  projectionHead : Option Digest
  attestationDigest : Digest
  sequence : Nat
  predecessor : Option Digest
  previousHead : Option ShortHead
  chain : ChainDestination
  evidence : Evidence
  availability : String
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

/-- A supplied prefix entry, with event bytes represented by a token. Core replay,
    chain hashing and root derivation are external to this typed component. -/
structure Entry where
  event : String
  eventHash : Digest
  recordHash : Digest
  canonicalTime : Nat
  stateRoot : Digest
  projectionHead : Option Digest
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

structure Submission where
  statement : Statement
  history : List Entry
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

structure Scope where
  domain : Domain
  historyId : Digest
  genesisEventHash : Digest
  profile : Profile
  chain : ChainDestination
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

def Statement.scope (s : Statement) : Scope :=
  ⟨s.domain, s.historyId, s.genesisEventHash, s.profile, s.chain⟩

def u53 : Nat := 9007199254740991

/-- Typed structural bounds and A-144 sequence-zero optionality. Raw JSON shape,
    identifier grammar and digest encoding are transport preconditions. -/
def shape (s : Statement) : Bool := decide (
  s.version = "irontrellis-anchor-statement/1" ∧ s.sequence ≤ u53 ∧
  s.head.position ≤ u53 ∧ s.head.canonicalTime ≤ u53 ∧
  (s.predecessor = none ↔ s.sequence = 0) ∧
  (s.previousHead = none ↔ s.sequence = 0))

/-- Compare the head and roots to the actual supplied prefix, not a claimed
    precomputed ancestry flag. Positions are zero-based. -/
def binding (x : Submission) : Bool :=
  match x.history.head?, x.history.getLast? with
  | some first, some last => decide (
      first.recordHash = x.statement.historyId ∧
      first.eventHash = x.statement.genesisEventHash ∧
      x.statement.head.position + 1 = x.history.length ∧
      last.recordHash = x.statement.head.hash ∧
      last.canonicalTime = x.statement.head.canonicalTime ∧
      last.stateRoot = x.statement.stateRoot ∧
      last.projectionHead = x.statement.projectionHead)
  | _, _ => false

abbrev Prefix (a b : List Entry) : Prop := a <+: b

/-- Exact full-prefix comparison; no hash injectivity is needed for this check. -/
def prefixOK (old next : Submission) : Bool := decide (Prefix old.history next.history)

def link (digest : Statement → Digest) (old next : Statement) : Bool := decide (
  next.sequence = old.sequence + 1 ∧
  next.predecessor = some (digest old) ∧
  next.previousHead = some old.head.short)

/-- Evidence primitive covers authenticated replay/attestation only. It is not
    an ancestry predicate, certificate-completeness premise, or chain finality. -/
abbrev EvidenceOK := Statement → List Entry → Bool

def valid (scope : Scope) (evidenceOK : EvidenceOK) (x : Submission) : Bool :=
  decide (x.statement.scope = scope) && shape x.statement && binding x &&
    evidenceOK x.statement x.history

end Anchor
