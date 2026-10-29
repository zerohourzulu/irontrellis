import OwnerPolicy.IronTrellis.Model
namespace IronTrellis
@[simp] theorem firstFailure_none (gs : List Gate) :
    firstFailure gs = none ↔ ∀ g ∈ gs, g.2 = true := by
  induction gs with
  | nil => simp [firstFailure]
  | cons g gs ih => rcases g with ⟨code, ok⟩; cases ok <;> simp [firstFailure, ih]

theorem accepted_gate {s : State} {e : Event} (h : Accepted s e)
    (g : Gate) (mem : g ∈ checks s e) : g.2 = true :=
  (firstFailure_none _).mp h g mem

theorem accepted_authorization {s : State} {e : Event}
    (h : Accepted s e) (ctl : e.body.tag.control = true) : authorization s e = true := by
  apply accepted_gate h (.controlAuthorizationInvalid, authorization s e)
  simp [checks, ctl]
theorem accepted_t1 {s : State} {e : Event} (h : Accepted s e) : t1 s e = true := by
  apply accepted_gate h (.transitionInvalid, t1 s e); simp [checks]
theorem accepted_t2 {s : State} {e : Event} (h : Accepted s e)
    (ctl : e.body.tag.control = true) : t2 s e = true := by
  apply accepted_gate h (.transitionInvalid, t2 s e); simp [checks, ctl]
theorem accepted_transition {s : State} {e : Event} (h : Accepted s e) : transitionOK s e = true := by
  apply accepted_gate h (.transitionInvalid, transitionOK s e); simp [checks]
theorem accepted_resulting_policy {s : State} {e : Event} (h : Accepted s e)
    (rot : e.body.tag = .rotate) : resultingPolicyValid s e = true := by
  apply accepted_gate h (.eventDataInvalid, resultingPolicyValid s e); simp [checks, rot]

theorem authorization_fields {s : State} {e : Event} (h : authorization s e = true) :
    e.control.isSome = true ∧ (∀ sig ∈ signers e, verifies s e sig = true) ∧
    (e.additional.isSome = decide (meff s e ≥ 2)) ∧
    unique ((signers e).map (·.keyId)) = true ∧ unique ((signers e).map (·.credential)) = true ∧
    meff s e ≤ (counting s e).length ∧
    ∃ sig ∈ counting s e, (signerClass s e sig).humanClass = true := by
  simpa only [authorization, Bool.and_eq_true, List.all_eq_true, List.any_eq_true,
    beq_iff_eq, decide_eq_true_eq, and_assoc] using h

theorem I01_one_signature {s : State} {e : Event} (h : Accepted s e)
    (ctl : e.body.tag.control = true) :
    ∃ sig, e.control = some sig ∧ verifies s e sig = true ∧ 1 ≤ (signers e).length := by
  have fields := authorization_fields (accepted_authorization h ctl)
  cases hcontrol : e.control with
  | none => simp [hcontrol] at fields
  | some sig =>
    refine ⟨sig, rfl, fields.2.1 sig ?_, ?_⟩ <;> simp [signers, hcontrol]

def PositivePolicy (p : Policy) : Prop :=
  1 ≤ p.threshold ∧ ∀ q ∈ p.byType.getD [], 1 ≤ q.2

theorem policy_positive {s ks ds p t g} (h : policyValid s ks ds p t g = true) : PositivePolicy p := by
  simp only [policyValid, Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true] at h
  constructor
  · grind
  · intro q hq
    grind

theorem default_positive : PositivePolicy {} := by simp [PositivePolicy]
theorem reachable_positive {s : State} (hr : Reachable s) : PositivePolicy s.epoch.p := by
  induction hr with
  | genesis g valid =>
    cases hp : g.policy with
    | none => simpa [initialState, Epoch.p, hp] using default_positive
    | some p =>
      simp only [genesisValid, hp, Bool.and_eq_true] at valid
      simpa [initialState, Epoch.p, hp] using policy_positive valid.2
  | @step s e hr ha ih =>
    by_cases rot : e.body.tag = .rotate
    · have hp := accepted_resulting_policy ha rot
      cases he : e.body.policy with
      | none => simpa [apply, rot, Epoch.p, he] using default_positive
      | some p =>
        simp only [resultingPolicyValid, he] at hp
        simpa [apply, rot, Epoch.p, he] using policy_positive hp
    · simpa [apply, rot] using ih

theorem meff_positive {s : State} {e : Event} (hp : PositivePolicy s.epoch.p) : 1 ≤ meff s e := by
  unfold meff
  dsimp only
  split
  · exact hp.1
  · cases ho : s.epoch.p.override e.body.tag with
    | none => simpa using hp.1
    | some n =>
      unfold Policy.override at ho
      cases hf : (s.epoch.p.byType.getD []).find? (fun q => q.1 == e.body.tag) with
      | none => simp [hf] at ho
      | some q =>
        have pos := hp.2 q (List.mem_of_find?_eq_some hf)
        simp [hf] at ho
        simpa [ho] using pos

theorem I02_threshold_floor {s : State} (hr : Reachable s) (e : Event) :
    1 ≤ s.epoch.p.threshold ∧ (∀ q ∈ s.epoch.p.byType.getD [], 1 ≤ q.2) ∧ 1 ≤ meff s e :=
  ⟨(reachable_positive hr).1, (reachable_positive hr).2, meff_positive (reachable_positive hr)⟩

theorem verifies_resolved {s : State} {e : Event} {sig : Signature}
    (h : verifies s e sig = true) :
    ∃ k, resolve s e sig = some k ∧ k ∈ adm s e ∧ k.valid = true ∧
      sig.credential = k.cred ∧ sig.challenge = challenge s e := by
  unfold verifies at h
  split at h
  · contradiction
  · rename_i k hk
    simp only [Bool.and_eq_true, beq_iff_eq] at h
    exact ⟨k, hk, List.mem_of_find?_eq_some hk, h.1.1.1, h.1.2, h.2⟩

theorem I03_same_challenge_S {s : State} {e : Event} (h : Accepted s e)
    (ctl : e.body.tag.control = true) : ∀ sig ∈ signers e, sig.challenge = challenge s e := by
  intro sig hs
  obtain ⟨_, _, _, _, _, hb⟩ := verifies_resolved ((authorization_fields (accepted_authorization h ctl)).2.1 sig hs)
  exact hb

theorem I04_admissibility {s : State} {e : Event} (h : Accepted s e)
    (ctl : e.body.tag.control = true) :
    ∀ sig ∈ signers e, ∃ k, resolve s e sig = some k ∧ k ∈ adm s e := by
  intro sig hs
  obtain ⟨k, hk, hm, _⟩ := verifies_resolved ((authorization_fields (accepted_authorization h ctl)).2.1 sig hs)
  exact ⟨k, hk, hm⟩

theorem I06_distinct {s : State} {e : Event} (h : Accepted s e)
    (ctl : e.body.tag.control = true) :
    unique ((signers e).map (·.keyId)) = true ∧ unique ((signers e).map (·.credential)) = true := by
  have hf := authorization_fields (accepted_authorization h ctl)
  exact ⟨hf.2.2.2.1, hf.2.2.2.2.1⟩
theorem I07_quorum {s : State} {e : Event} (h : Accepted s e)
    (ctl : e.body.tag.control = true) : meff s e ≤ (counting s e).length :=
  (authorization_fields (accepted_authorization h ctl)).2.2.2.2.2.1

theorem I08_agent_never_alone {s : State} {e : Event} (h : Accepted s e)
    (ctl : e.body.tag.control = true) :
    ∃ sig ∈ counting s e, signerClass s e sig ≠ .agent ∧ signerClass s e sig ≠ .none := by
  obtain ⟨sig, hs, hc⟩ := (authorization_fields (accepted_authorization h ctl)).2.2.2.2.2.2
  refine ⟨sig, hs, ?_⟩
  cases hcl : signerClass s e sig <;> simp [hcl, Class.humanClass] at hc ⊢

theorem declared_class (p : Policy) (ks : List Key) (t : Nat) (c : Cred)
    (h : p.att = false) : cls p ks t c = .human ∨ cls p ks t c = .agent := by
  simp [cls, h]

theorem I09_rotation_no_agent {s : State} {e : Event} (rot : e.body.tag = .rotate) :
    ∀ sig ∈ counting s e, signerClass s e sig ≠ .agent ∧ signerClass s e sig ≠ .none := by
  intro sig hs
  have cc := (List.mem_filter.mp hs).2
  cases hat : s.epoch.p.att
  · obtain hc | hc := declared_class s.epoch.p s.epoch.keys e.time sig.credential hat
    · simp [signerClass, hc]
    · simp [counts, hat, rot, signerClass, hc] at cc
  · cases hr : isRestoration s e <;> cases hc : signerClass s e sig <;>
      simp [counts, hat, rot, hr, hc, Class.humanClass] at cc ⊢

theorem I10_lapsed_only_exempt {s : State} {e : Event} :
    ∀ sig ∈ counting s e, signerClass s e sig = .lapsed → exempt s e = true := by
  intro sig hs hc
  have cc := (List.mem_filter.mp hs).2
  cases hat : s.epoch.p.att
  · obtain h | h := declared_class s.epoch.p s.epoch.keys e.time sig.credential hat <;>
      simp [signerClass] at hc <;> simp [hc] at h
  · by_cases rot : e.body.tag = .rotate
    · have rest : isRestoration s e = true := by
        cases hr : isRestoration s e <;> simp_all [counts, Class.humanClass]
      simp [exempt, rest]
    · cases he : exempt s e <;> simp_all [counts]

theorem I11_human_nonexempt {s : State} {e : Event} (h : Accepted s e)
    (ctl : e.body.tag.control = true) (_hat : s.epoch.p.att = true) (hx : exempt s e = false) :
    ∃ sig ∈ counting s e, signerClass s e sig = .human := by
  obtain ⟨sig, hm, hh⟩ := (authorization_fields (accepted_authorization h ctl)).2.2.2.2.2.2
  refine ⟨sig, hm, ?_⟩
  cases hc : signerClass s e sig <;> simp [hc, Class.humanClass] at hh
  · rfl
  · have := I10_lapsed_only_exempt sig hm hc
    simp [hx] at this

theorem I14_class_credential_function (p : Policy) (ks : List Key) (t : Nat)
    (k₁ k₂ : Key) (h : k₁.cred = k₂.cred) :
    cls p ks t k₁.cred = cls p ks t k₂.cred := by rw [h]

theorem I16_policy_rotation_members {s : State} {e : Event} (h : isPolicyRot s e = true) :
    (apply s e).epoch.keys.length = s.epoch.keys.length ∧
    ∀ k ∈ (apply s e).epoch.keys, k ∈ s.epoch.keys := by
  simp only [isPolicyRot, Bool.and_eq_true, beq_iff_eq] at h
  have keeps := h.1.2
  simp only [keepsEveryKey, Bool.and_eq_true, beq_iff_eq, List.all_eq_true] at keeps
  simpa [apply, h.1.1] using keeps

theorem I17_challenge_pre_event (s : State) (e : Event) :
    (challenge s e).previousHead = s.head ∧ (challenge s e).effect = e.body := ⟨rfl,rfl⟩
theorem I22_codes (s : State) (e : Event) (c : Code) (_h : verdict s e = some c) :
    c = .eventDataInvalid ∨ c = .controlAuthorizationInvalid ∨ c = .transitionInvalid := by
  cases c <;> simp

theorem I31_reduced_not_rotation (r : Records) (b : Body) (t : Nat)
    (h : prEff r b t = true) : b.tag ≠ .rotate := by
  intro hr; simp [prEff, hr] at h

theorem I31_effect_function (r₁ r₂ : Records) (b₁ b₂ : Body) (t : Nat)
    (hr : r₁ = r₂) (hb : b₁ = b₂) : prEff r₁ b₁ t = prEff r₂ b₂ t := by rw [hr,hb]

theorem I33_only_owners_cross {s : State} {e : Event} (h : Accepted s e)
    (hat : s.epoch.p.att = true) (a : Attestation)
    (ha : a ∈ s.epoch.p.attestations.getD []) (ht : s.time < a.expiresAt)
    (cross : a.expiresAt ≤ e.time) : e.body.tag.control = true := by
  have h1 := accepted_t1 h
  simp only [t1, hat, Bool.not_true, Bool.false_or, Bool.or_eq_true, List.all_eq_true] at h1
  rcases h1 with ctl | all
  · exact ctl
  · have acheck := all a ha
    simp only [Bool.or_eq_true, decide_eq_true_eq] at acheck
    omega

theorem I36_structural_ignores_signature_payload (s : State) (e : Event)
    (sigs : Option Signature) (more : Option (List Signature)) :
    prEff s.records ({e with control := sigs, additional := more}.body) e.time = prEff s.records e.body e.time ∧
    meff s {e with control := sigs, additional := more} = meff s e := ⟨rfl,rfl⟩

theorem I42_single_human_horizon {s : State} {e : Event} (h : Accepted s e)
    (ctl : e.body.tag.control = true) (hat : s.epoch.p.att = true) (hc1 : hc s e ≤ 1) :
    e.time = s.time ∨ e.time ≤ min s.epoch.p.horizon (MAXT-1) := by
  have h2 := accepted_t2 h ctl
  simpa [t2, hat, ctl, show ¬hc s e > 1 by omega] using h2

theorem I05_no_self_admission {s : State} {e : Event} (h : Accepted s e)
    (ctl : e.body.tag.control = true) (sig : Signature) (hs : sig ∈ counting s e) :
    ∃ k, resolve s e sig = some k ∧
      (k ∈ s.epoch.keys ∨ (isRecovery s e = true ∧ k ∈ revealed s e ∧ digest k ∈ s.epoch.d)) := by
  have hsign : sig ∈ signers e := (List.mem_filter.mp hs).1
  obtain ⟨k, hk, hm, _⟩ := verifies_resolved ((authorization_fields (accepted_authorization h ctl)).2.1 sig hsign)
  refine ⟨k, hk, ?_⟩
  have kid : k.id = sig.keyId := by simpa [resolve] using List.find?_some hk
  simp only [adm, List.mem_append] at hm
  rcases hm with old | recovery
  · exact Or.inl old
  · right
    split at recovery
    · rename_i ext
      have hm := List.mem_filter.mp recovery
      refine ⟨?_, hm.1, by simpa using hm.2⟩
      simp only [isRecovery, Bool.and_eq_true, List.any_eq_true]
      have ee : e.body.tag = .rotate ∧ s.epoch.p.recovery = true := by simpa using ext
      exact ⟨⟨by simpa using ee.1, ee.2⟩, sig, hsign, k, hm.1, by simpa [kid] using hm.2⟩
    · simp at recovery

theorem accepted_schema {s : State} {e : Event} (h : Accepted s e) :
    eventSchema e = true ∧ e.time ≤ MAXT ∧
    (e.inPrefix = true → e.body.policy = none ∧ e.additional = none ∧ e.body.tag ≠ .rotate) := by
  have hg := accepted_gate h (.eventDataInvalid,
    eventSchema e && e.body.policy.all policyShape && optionalListShape e.additional 63 &&
    optionalListShape e.next 64 && e.time ≤ MAXT &&
    (!e.inPrefix || (e.body.policy.isNone && e.additional.isNone && e.body.tag != .rotate))) (by simp [checks])
  simp only [Bool.and_eq_true, Bool.or_eq_true, Bool.not_eq_true, decide_eq_true_eq,
    Option.isNone_iff_eq_none, Bool.not_eq_true, bne_iff_ne] at hg
  grind

theorem I21_prefix {s : State} {e : Event} (h : Accepted s e) (hp : e.inPrefix = true) :
    e.body.policy = none ∧ e.additional = none ∧ e.body.tag ≠ .rotate := (accepted_schema h).2.2 hp

theorem I03_same_challenge_NKA {s : State} {e : Event} (h : Accepted s e) :
    ∀ sig ∈ e.next.getD [], sig.challenge = challenge s e := by
  intro sig hs
  by_cases hr : e.body.tag = .rotate
  · have ht := accepted_transition h
    simp only [transitionOK, hr, Bool.and_eq_true] at ht
    have hc := ht.2.1.2
    simp only [commitmentOK, Bool.and_eq_true, List.all_eq_true] at hc
    have hn := hc.1.1.1 sig hs
    simp only [nextVerifies, List.any_eq_true, Bool.and_eq_true, beq_iff_eq] at hn
    obtain ⟨k, _, hk⟩ := hn
    exact hk.2
  · have he := (accepted_schema h).1
    simp [eventSchema, hr] at he
    simp_all

theorem I15_commitment_conservation {s : State} {e : Event} (h : Accepted s e)
    (rot : e.body.tag = .rotate) (committed : s.epoch.digests.isSome = true) :
    (isPolicyRot s e = true ∧ e.next = none ∧ e.body.digests.isSome = true ∧
      sameSet (e.body.digests.getD []) s.epoch.d = true) ∨
    ((revealed s e).isEmpty = false ∧
      (∀ k ∈ revealed s e, digest k ∈ s.epoch.d) ∧ e.next.isSome = true ∧
      e.body.digests.isSome = true ∧
      (guard s e = true → ∀ k ∈ revealed s e,
        ((e.next.getD []).filter (fun sig => sig.keyId == k.id)).length = 1)) := by
  have ht := accepted_transition h
  simp only [transitionOK, rot, Bool.and_eq_true] at ht
  have hc := ht.2.1.2
  simp only [commitmentOK, committed, Bool.and_eq_true, ite_true] at hc
  cases hp : isPolicyRot s e
  · right
    simp [hp, Bool.and_eq_true, Bool.or_eq_true, List.all_eq_true] at hc
    grind
  · left
    simp [hp, Bool.and_eq_true] at hc
    grind

def RootQualified (pinEpoch appendEpoch : Epoch) (pinTime : Nat) (credential : Cred) : Bool :=
  (if pinEpoch.p.att then cls pinEpoch.p pinEpoch.keys pinTime credential == .human
   else cls pinEpoch.p pinEpoch.keys pinTime credential != .agent) &&
  (if appendEpoch.p.att then (appendEpoch.p.stmt credential).isSome
   else !(appendEpoch.p.agentCred appendEpoch.keys credential)) &&
  (appendEpoch.p.override .checkpoint).getD appendEpoch.p.threshold == 1

theorem I19_root_qualification (old current : Epoch) (t c : Nat)
    (h : RootQualified old current t c = true) :
    (old.p.att = true → cls old.p old.keys t c = .human) ∧
    (current.p.att = true → (current.p.stmt c).isSome = true) := by
  simp only [RootQualified, Bool.and_eq_true] at h
  constructor
  · intro ha; simpa [ha] using h.1.1
  · intro ha; simpa [ha] using h.1.2

theorem I35_asserted_root_threshold (old current : Epoch) (t c : Nat)
    (h : RootQualified old current t c = true) :
    (current.p.override .checkpoint).getD current.p.threshold = 1 := by
  simp only [RootQualified, Bool.and_eq_true] at h
  simpa using h.2

theorem I42_m1_count_bound {s : State} {e : Event} (h : Accepted s e)
    (ctl : e.body.tag.control = true) (m1 : meff s e = 1) : hc s e ≤ 1 := by
  have ha := authorization_fields (accepted_authorization h ctl)
  have noadd : e.additional = none := by
    have hp := ha.2.2.1
    simp [m1] at hp
    exact hp
  have sigbound : (signers e).length ≤ 1 := by
    cases hc : e.control <;> simp [signers, noadd, hc]
  exact Nat.le_trans (List.length_filter_le _ _) (Nat.le_trans (List.length_filter_le _ _) sigbound)

/- Local, exact policy-validation consequences. Whole-history preservation of
   all foreign-record restrictions is separately inventoried. -/
theorem I13_policy_time_bounds {s ks ds p t g} (h : policyValid s ks ds p t g = true) :
    p.mrot ≤ (ks.filter (fun k => !(p.agentCred ks k.cred))).length ∧
    (p.att = true → p.mrot ≤ (ks.filter (fun k => p.validAt k.cred t)).length ∧
      2 ≤ (p.attesters.getD []).length) ∧
    (∀ q ∈ p.byType.getD [], q.2 < p.threshold → q.1.lowType = true) ∧
    (∀ a ∈ p.attesters.getD [], a.cred ∉ s.records.foreign ∧ a.cred ∉ ks.map (·.cred) ∧ a.cred ∉ ds) := by
  simp only [policyValid, Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true,
    Bool.or_eq_true, Bool.not_eq_true, List.contains_iff_mem] at h
  grind

theorem I18_attestation_binding {s ks ds p t g} (h : policyValid s ks ds p t g = true)
    (a : Attestation) (ha : a ∈ p.attestations.getD []) :
    a.audience = s.domain ∧ a.signed = true ∧
    (∃ att ∈ p.attesters.getD [], att.id = a.attesterId) ∧
    (a.subject ∈ ks ∨ a.subject.cred ∈ ds) ∧
    a.notBefore < a.expiresAt ∧ a.expiresAt ≤ MAXT ∧
    (t < a.expiresAt ∨ (g = false ∧ a ∈ s.epoch.p.attestations.getD [])) ∧
    p.agentCred ks a.subject.cred = false ∧
    (if g then a.historyId = none else
      a ∈ s.epoch.p.attestations.getD [] ∨ a.historyId = some s.historyId) := by
  simp only [policyValid, Bool.and_eq_true, List.all_eq_true] at h
  have ah := h.2 a ha
  simpa [Bool.and_eq_true, Bool.or_eq_true, List.any_eq_true, and_assoc] using ah


end IronTrellis
