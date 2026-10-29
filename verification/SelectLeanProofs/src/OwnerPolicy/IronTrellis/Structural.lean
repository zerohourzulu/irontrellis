import OwnerPolicy.IronTrellis.Safety
namespace IronTrellis

/- This bundle states the structural part of I12 directly. Class monotonicity
   is proved below for a carried or valid renewed statement independently. -/
theorem I12_restoration_structure {s : State} {e : Event} (h : isRestoration s e = true) :
    isPolicyRot s e = true ∧ s.epoch.p.att = true ∧
    ∃ p, e.body.policy = some p ∧ p.att = true ∧ policyCore p = policyCore s.epoch.p ∧
      e.body.digests.isSome = s.epoch.digests.isSome ∧
      sameSet (e.body.digests.getD []) s.epoch.d = true ∧
      sameSet p.subjects s.epoch.p.subjects = true ∧
      ∀ a' ∈ p.attestations.getD [], a' ∈ s.epoch.p.attestations.getD [] ∨
        ∃ a, s.epoch.p.stmt a'.subject.cred = some a ∧ renewal a' a s.epoch.tset e.time = true := by
  unfold isRestoration at h
  cases hp : e.body.policy with
  | none => simp [hp] at h
  | some p =>
    simp only [hp, Bool.and_eq_true, beq_iff_eq, List.all_eq_true, Bool.or_eq_true] at h
    refine ⟨h.1.1,h.1.2,p,rfl,?_,?_,?_,?_,?_,?_⟩
    all_goals grind

theorem renewal_started (a' a : Attestation) (tset t : Nat)
    (h : renewal a' a tset t = true) : a'.notBefore ≤ t ∧ a.expiresAt < a'.expiresAt := by
  simp only [renewal,Bool.and_eq_true,beq_iff_eq,decide_eq_true_eq] at h
  exact ⟨h.1.2,h.2⟩

theorem renewed_is_human (p : Policy) (ks : List Key) (a' a : Attestation) (tset t : Nat)
    (att : p.att = true) (statement : p.stmt a'.subject.cred = some a')
    (renew : renewal a' a tset t = true) (expires : t < a'.expiresAt) :
    cls p ks t a'.subject.cred = .human := by
  have nb := (renewal_started a' a tset t renew).1
  simp [cls,att,Policy.validAt,statement,validAt,nb,expires]

theorem renewal_class_nondecreasing (p' p : Policy) (ks : List Key) (a' a : Attestation) (tset t : Nat)
    (att : p'.att = true) (statement : p'.stmt a'.subject.cred = some a')
    (renew : renewal a' a tset t = true) (expires : t < a'.expiresAt)
    (oldNonAgent : cls p ks t a'.subject.cred ≠ .agent) :
    (cls p ks t a'.subject.cred).rank ≤ (cls p' ks t a'.subject.cred).rank := by
  rw [renewed_is_human p' ks a' a tset t att statement renew expires]
  cases hc : cls p ks t a'.subject.cred <;> simp [hc,Class.rank] at oldNonAgent ⊢

/- I32's temporal step: a started valid-shaped, non-agent statement can only
   classify HUMAN or LAPSED at every future timestamp. -/
theorem started_human_or_lapsed (p : Policy) (ks : List Key) (c tset t : Nat)
    (att : p.att = true) (started : p.started c tset = true)
    (future : tset ≤ t) (nonAgent : p.agentCred ks c = false) :
    (cls p ks t c).humanClass = true := by
  unfold Policy.started at started
  cases hs : p.stmt c with
  | none => simp [hs] at started
  | some a =>
    have before : a.notBefore ≤ tset := by simpa [hs] using started
    have nb : a.notBefore ≤ t := Nat.le_trans before future
    by_cases expiry : t < a.expiresAt
    · simp [cls,att,Policy.validAt,hs,validAt,nb,expiry,Class.humanClass]
    · have expired : a.expiresAt ≤ t := by omega
      simp [cls,att,Policy.validAt,hs,validAt,nb,expiry,nonAgent,expired,Class.humanClass]

theorem policy_clear_foreign {s : State} {ks ds p t g}
    (h : policyValid s ks ds p t g = true) : policyValid (sfState s) ks ds p t g = true := by
  simp only [policyValid,Bool.and_eq_true,List.all_eq_true] at h ⊢
  simp only [sfState,Records.foreign,List.map_nil,List.flatMap_nil,List.nil_append,List.contains_nil,Bool.not_false,Bool.and_true]
  grind

theorem resulting_policy_clear_foreign {s : State} {e : Event}
    (h : resultingPolicyValid s e = true) : resultingPolicyValid (sfState s) e = true := by
  cases hp : e.body.policy with
  | none => simp [resultingPolicyValid,hp]
  | some p =>
    simp only [resultingPolicyValid,hp] at h ⊢
    exact policy_clear_foreign h

theorem foreign_digest_resulting_attester {s : State} {e : Event}
    (h : foreignDigestOK s e = true) :
    (introduced s e).all (fun d => !((e.body.policy.getD {}).attCreds.contains d)) = true := by
  by_cases hg : guard s e = true
  · simp only [foreignDigestOK,hg,Bool.not_true,Bool.false_or,List.all_eq_true] at h ⊢
    intro d hd
    have hh := h d hd
    simp only [List.contains_append,Bool.not_or,Bool.and_eq_true] at hh
    exact hh.2
  · have pn : e.body.policy = none := by
      simp only [guard,Bool.or_eq_true,Option.isSome_iff_exists] at hg
      cases hp : e.body.policy <;> simp_all
    simp [pn,Policy.attCreds]

theorem accepted_implies_acceptSF {s : State} {e : Event} (h : Accepted s e)
    (rot : e.body.tag = .rotate) : acceptSF s e := by
  have schema := accepted_gate h (.eventDataInvalid,
    eventSchema e && e.body.policy.all policyShape && optionalListShape e.additional 63 &&
    optionalListShape e.next 64 && e.time ≤ MAXT &&
    (!e.inPrefix || (e.body.policy.isNone && e.additional.isNone && e.body.tag != .rotate))) (by simp [checks])
  have time := accepted_gate h (.transitionInvalid, decide (s.time ≤ e.time)) (by simp [checks])
  have ctl : e.body.tag.control = true := by simp [rot,Tag.control]
  have auth := accepted_authorization h ctl
  have clock := accepted_t2 h ctl
  have keycheck := accepted_gate h (.eventDataInvalid,
    keyShape e.body.ownerKeys && digestShape e.body.digests && foreignOwnerOK s e) (by simp [checks,rot])
  have pol := resulting_policy_clear_foreign (accepted_resulting_policy h rot)
  have tran := accepted_transition h
  simp only [transitionOK,rot,Bool.and_eq_true] at tran
  have digest := foreign_digest_resulting_attester tran.2.2
  have capacity := accepted_gate h (.transitionInvalid,e.capacityOK) (by simp [checks])
  simp only [acceptSF,firstFailure_none]
  intro gate hg
  simp only [sfChecks,List.mem_cons,List.mem_singleton,List.not_mem_nil,or_false] at hg
  simp only [Bool.and_eq_true] at keycheck
  rcases hg with h₁ | h₂ | h₃ | h₄ | h₅ | h₆ | h₇ | h₈
  · simpa [h₁] using schema
  · simpa [h₂] using time
  · simpa [h₃] using auth
  · simpa [h₄] using clock
  · simp [h₅,keycheck.1.1,keycheck.1.2]
  · simpa [h₆] using pol
  · rw [h₇]
    simp only [Bool.and_eq_true]
    exact ⟨⟨⟨tran.1.1,tran.2.1.1⟩,tran.2.1.2⟩,digest⟩
  · simpa [h₈] using capacity

@[simp] theorem unique_iff_nodup [BEq α] [LawfulBEq α] (xs : List α) :
    unique xs = true ↔ xs.Nodup := by
  induction xs with
  | nil => simp [unique]
  | cons x xs ih => simp [unique,ih,List.nodup_cons]

theorem map_nodup_implies_nodup {xs : List α} (f : α → β)
    (h : (xs.map f).Nodup) : xs.Nodup := by
  induction xs with
  | nil => simp
  | cons x xs ih =>
    simp only [List.map_cons,List.nodup_cons] at h ⊢
    refine ⟨?_,ih h.2⟩
    intro hx
    exact h.1 (List.mem_map.mpr ⟨x,hx,rfl⟩)

theorem subset_same_length_reverse [DecidableEq α] {xs ys : List α}
    (unique : xs.Nodup) (sub : xs ⊆ ys) (len : xs.length = ys.length) : ys ⊆ xs := by
  intro y hy
  apply Classical.byContradiction
  intro absent
  have smaller : xs ⊆ ys.erase y := by
    intro x hx
    have ne : x ≠ y := by intro eq; exact absent (eq ▸ hx)
    exact (List.mem_erase_of_ne ne).mpr (sub hx)
  have bound := List.Nodup.length_le_of_subset unique smaller
  have eraseLen : (ys.erase y).length = ys.length-1 := by rw [List.length_erase]; simp [hy]
  have pos := List.length_pos_of_mem hy
  omega

theorem I16_policy_rotation_same_keys {s : State} {e : Event}
    (h : Accepted s e) (policy : isPolicyRot s e = true) :
    sameSet (apply s e).epoch.keys s.epoch.keys = true := by
  have bundle := I16_policy_rotation_members policy
  have rot : e.body.tag = .rotate := by
    simp only [isPolicyRot,Bool.and_eq_true,beq_iff_eq] at policy
    exact policy.1.1
  have shape := accepted_gate h (.eventDataInvalid,
    keyShape e.body.ownerKeys && digestShape e.body.digests && foreignOwnerOK s e) (by simp [checks,rot])
  simp only [Bool.and_eq_true] at shape
  have ids : unique (e.body.ownerKeys.map (·.id)) = true := by
    have kk := shape.1.1
    simp only [keyShape,Bool.and_eq_true] at kk
    exact kk.1.2
  have nodup := map_nodup_implies_nodup (fun k : Key => k.id) ((unique_iff_nodup _).mp ids)
  have postdup : (apply s e).epoch.keys.Nodup := by simpa [apply,rot] using nodup
  have reverse := subset_same_length_reverse postdup bundle.2 bundle.1
  simp only [sameSet,Bool.and_eq_true,List.all_eq_true,List.contains_iff_mem]
  exact ⟨bundle.2,reverse⟩

end IronTrellis
