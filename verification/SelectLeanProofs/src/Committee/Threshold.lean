import OwnerPolicy.IronTrellis.Construction
import OwnerPolicy.IronTrellis.Policy

namespace Committee
open IronTrellis

/- Current A-106/A-116 threshold projection. `pr` is the outcome of the
   current edition's separate PR_eff procedure, not the historical model's
   terminated-agent guard. A-114.4 explicitly permits this parameter for
   threshold theorems. No desired authorization result is supplied. -/
def effective (s : State) (e : Event) (pr : Bool) : Nat :=
  let p := s.epoch.p
  let m := (p.override e.body.tag).getD p.threshold
  if e.body.tag.prType && m < p.threshold && !pr then p.threshold else m

def exemption (s : State) (e : Event) (pr : Bool) : Bool :=
  pr || isRestoration s e || e.body.tag == .checkpoint

def eligible (s : State) (e : Event) (pr : Bool) (k : Key) : Bool :=
  counts s.epoch.p.att (e.body.tag == .rotate) (isRestoration s e) (exemption s e pr)
    (cls s.epoch.p s.epoch.keys e.time k.cred)

def counted (s : State) (e : Event) (pr : Bool) : List Signature :=
  (signers e).filter (fun sig => counts s.epoch.p.att (e.body.tag == .rotate)
    (isRestoration s e) (exemption s e pr) (signerClass s e sig))

def humanCount (s : State) (e : Event) (pr : Bool) : Nat :=
  ((counted s e pr).filter (fun sig => (signerClass s e sig).humanClass)).length

def authorized (s : State) (e : Event) (pr : Bool) : Bool :=
  e.control.isSome && (signers e).all (verifies s e) &&
  (e.additional.isSome == (effective s e pr ≥ 2)) &&
  unique ((signers e).map (·.keyId)) && unique ((signers e).map (·.credential)) &&
  effective s e pr ≤ (counted s e pr).length &&
  (counted s e pr).any (fun sig => (signerClass s e sig).humanClass)

def clock (s : State) (e : Event) (pr : Bool) : Bool :=
  !s.epoch.p.att || !(e.body.tag.control) || humanCount s e pr > 1 ||
    e.time == s.time || e.time ≤ min s.epoch.p.horizon (MAXT-1)

/- This is only the owner threshold/time stage. Ordinary r4 event/schema,
   commitment, resulting-policy and capacity gates remain distinct. -/
def stage (s : State) (e : Event) (pr : Bool) : Option Code :=
  if !authorized s e pr then some .controlAuthorizationInvalid
  else if !clock s e pr then some .transitionInvalid else none

/- The profile is credential based. In particular it excludes the declared
   recovery-signer loophole: a revealed committed credential outside K is not
   classed AGENT by a key-class map for K. A-140.3 forbids that deployment. -/
structure Profile (s : State) (committee : Key) : Prop where
  member : committee ∈ s.epoch.keys
  classified : s.epoch.p.agentCred s.epoch.keys committee.cred = true
  noStatement : s.epoch.p.stmt committee.cred = none
  noRecoveryCommitment : committee.cred ∉ s.epoch.d

@[simp] theorem effective_legacy (s : State) (e : Event) :
    effective s e (prEff s.records e.body e.time) = meff s e := rfl
@[simp] theorem exemption_legacy (s : State) (e : Event) :
    exemption s e (prEff s.records e.body e.time) = exempt s e := rfl
@[simp] theorem counted_legacy (s : State) (e : Event) :
    counted s e (prEff s.records e.body e.time) = counting s e := rfl
@[simp] theorem authorized_legacy (s : State) (e : Event) :
    authorized s e (prEff s.records e.body e.time) = authorization s e := rfl
@[simp] theorem clock_legacy (s : State) (e : Event) :
    clock s e (prEff s.records e.body e.time) = t2 s e := rfl

theorem authorization_fields {s : State} {e : Event} {pr : Bool}
    (h : authorized s e pr = true) :
    e.control.isSome = true ∧ (∀ sig ∈ signers e, verifies s e sig = true) ∧
    e.additional.isSome = decide (effective s e pr ≥ 2) ∧
    unique ((signers e).map (·.keyId)) = true ∧ unique ((signers e).map (·.credential)) = true ∧
    effective s e pr ≤ (counted s e pr).length ∧
    ∃ sig ∈ counted s e pr, (signerClass s e sig).humanClass = true := by
  simpa only [authorized, Bool.and_eq_true, List.all_eq_true, List.any_eq_true,
    beq_iff_eq, decide_eq_true_eq, and_assoc] using h

theorem profile_class {s : State} {committee : Key} (h : Profile s committee) (t : Nat) :
    cls s.epoch.p s.epoch.keys t committee.cred = .agent := by
  simp [cls,Policy.validAt,h.noStatement,h.classified]

theorem no_statement_not_human {p : Policy} {ks : List Key} {t c : Nat}
    (attested : p.att = true) (absent : p.stmt c = none) : cls p ks t c ≠ .human := by
  simp [cls,Policy.validAt,attested,absent]
  split <;> simp

theorem human_requires_statement {p : Policy} {ks : List Key} {t c : Nat}
    (attested : p.att = true) (human : cls p ks t c = .human) :
    ∃ a, p.stmt c = some a ∧ validAt a t = true := by
  cases hs : p.stmt c with
  | none => exact False.elim (no_statement_not_human attested hs human)
  | some a =>
    refine ⟨a,rfl,?_⟩
    cases hv : validAt a t
    · simp only [cls,attested,Bool.not_true,Bool.false_eq_true,↓reduceIte,
        Policy.validAt,hs,hv] at human
      split at human
      · contradiction
      · split at human <;> contradiction
    · rfl

theorem committee_never_alone {s : State} {e : Event} {pr : Bool} {committee : Key}
    (profile : Profile s committee)
    (alone : ∀ sig ∈ signers e, sig.credential = committee.cred) :
    authorized s e pr = false := by
  apply Bool.eq_false_iff.mpr
  intro h
  obtain ⟨sig,hm,hc⟩ := (authorization_fields h).2.2.2.2.2.2
  have eqcred := alone sig (List.mem_filter.mp hm).1
  have ha := profile_class profile e.time
  simp [signerClass,eqcred,ha,Class.humanClass] at hc

theorem committee_never_counts_rotation {s : State} {e : Event} {pr : Bool} {committee : Key}
    (profile : Profile s committee) (rotation : e.body.tag = .rotate)
    (sig : Signature) (credential : sig.credential = committee.cred) :
    sig ∉ counted s e pr := by
  have ha := profile_class profile e.time
  simp [counted,counts,rotation,signerClass,credential,ha,Class.humanClass]

/- Full wire acceptance cannot be inferred merely from a holder count.
   An exact distinct quorum is constructed from verifying ideal signatures. -/
structure QuorumKeys (s : State) (e : Event) (pr : Bool) (first : Key) (rest : List Key) : Prop where
  resolved : ∀ k ∈ first::rest, (adm s e).find? (fun x => x.id == k.id) = some k
  valid : ∀ k ∈ first::rest, k.valid = true
  ids : unique ((first::rest).map (·.id)) = true
  credentials : unique ((first::rest).map (·.cred)) = true
  number : (first::rest).length = effective s e pr

theorem constructed_counted (s : State) (e : Event) (pr : Bool) (first : Key) (rest : List Key)
    (ok : ∀ k ∈ first::rest, eligible s e pr k = true) :
    counted s (withSignatures s e first rest) pr = (first::rest).map (makeSignature s e) := by
  unfold counted
  rw [signers_constructed]
  apply List.filter_eq_self.mpr
  intro sig hs
  obtain ⟨k,hk,rfl⟩ := List.mem_map.mp hs
  exact ok k hk

theorem constructed_authorization (s : State) (e : Event) (pr : Bool) (first : Key) (rest : List Key)
    (q : QuorumKeys s e pr first rest)
    (ok : ∀ k ∈ first::rest, eligible s e pr k = true)
    (human : (cls s.epoch.p s.epoch.keys e.time first.cred).humanClass = true) :
    authorized s (withSignatures s e first rest) pr = true := by
  have heff : effective s (withSignatures s e first rest) pr = effective s e pr := rfl
  have presence : (withSignatures s e first rest).additional.isSome = decide (2 ≤ effective s e pr) := by
    have number := q.number
    cases rest <;> simp_all [withSignatures] <;> omega
  have allVerified : (signers (withSignatures s e first rest)).all
      (verifies s (withSignatures s e first rest)) = true := by
    rw [signers_constructed]
    simp only [List.all_eq_true,List.mem_map,forall_exists_index,and_imp]
    intro sig k hk heq
    subst sig
    exact constructed_verifies s e first rest k (q.resolved k hk) (q.valid k hk)
  have hcount := constructed_counted s e pr first rest ok
  have ids : unique ((signers (withSignatures s e first rest)).map (·.keyId)) = true := by
    simpa [signers_constructed,List.map_map,Function.comp_def,makeSignature] using q.ids
  have creds : unique ((signers (withSignatures s e first rest)).map (·.credential)) = true := by
    simpa [signers_constructed,List.map_map,Function.comp_def,makeSignature] using q.credentials
  have someHuman : (counted s (withSignatures s e first rest) pr).any
      (fun sig => (signerClass s (withSignatures s e first rest) sig).humanClass) = true := by
    rw [hcount]
    simp only [List.any_eq_true]
    exact ⟨makeSignature s e first,by simp,human⟩
  simp only [authorized,heff,allVerified,presence,beq_self_eq_true,ids,creds,hcount,List.length_map,
    q.number,Nat.le_refl,decide_true,Bool.and_true]
  rw [← hcount,someHuman]
  simp [withSignatures]

theorem human_class_reduction_eligible (s : State) (e : Event) (k : Key)
    (nonrotation : e.body.tag ≠ .rotate)
    (human : (cls s.epoch.p s.epoch.keys e.time k.cred).humanClass = true) :
    eligible s e true k = true := by
  cases hc : cls s.epoch.p s.epoch.keys e.time k.cred <;>
    simp_all [eligible,counts,exemption,Class.humanClass]

theorem human_rotation_eligible (s : State) (e : Event) (pr : Bool) (k : Key)
    (human : cls s.epoch.p s.epoch.keys e.time k.cred = .human) :
    eligible s e pr k = true := by
  cases hat : s.epoch.p.att <;> cases hr : e.body.tag == .rotate <;>
    cases hrest : isRestoration s e <;> cases hx : exemption s e pr <;>
    simp [eligible,counts,hat,hr,hrest,hx,human,Class.humanClass]

theorem reduction_without_committee (s : State) (e : Event) (first : Key) (rest : List Key)
    (committee : Key) (profile : Profile s committee) (nonrotation : e.body.tag ≠ .rotate)
    (q : QuorumKeys s e true first rest)
    (humans : ∀ k ∈ first::rest, (cls s.epoch.p s.epoch.keys e.time k.cred).humanClass = true) :
    authorized s (withSignatures s e first rest) true = true ∧
    ∀ sig ∈ signers (withSignatures s e first rest), sig.credential ≠ committee.cred := by
  constructor
  · apply constructed_authorization s e true first rest q
    · exact fun k hk => human_class_reduction_eligible s e k nonrotation (humans k hk)
    · exact humans first (by simp)
  · intro sig hs eqc
    rw [signers_constructed] at hs
    obtain ⟨k,hk,rfl⟩ := List.mem_map.mp hs
    have hh := humans k hk
    have ha := profile_class profile e.time
    simpa [makeSignature] using (show False from by
      have ec : k.cred = committee.cred := eqc
      simp [ec,ha,Class.humanClass] at hh)

theorem clock_at_head (s : State) (e : Event) (pr : Bool) (atHead : e.time = s.time) :
    clock s e pr = true := by simp [clock,atHead]

theorem human_quorum_authorization (s : State) (e : Event) (first : Key) (rest : List Key)
    (q : QuorumKeys s e false first rest)
    (humans : ∀ k ∈ first::rest, cls s.epoch.p s.epoch.keys e.time k.cred = .human) :
    authorized s (withSignatures s e first rest) false = true := by
  apply constructed_authorization s e false first rest q
  · exact fun k hk => human_rotation_eligible s e false k (humans k hk)
  · simp [humans first (by simp),Class.humanClass]

end Committee
