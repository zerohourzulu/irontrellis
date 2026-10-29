import OwnerPolicy.IronTrellis.Structural
namespace IronTrellis

def LocalRules (p : Policy) (ks : List Key) (tset : Nat) : Prop :=
  PositivePolicy p ∧ unique (ks.map (·.cred)) = true ∧
  p.mrot ≤ (ks.filter (fun k => !(p.agentCred ks k.cred))).length ∧
  (p.att = true → p.mrot ≤ (ks.filter (fun k => p.validAt k.cred tset)).length) ∧
  (∀ q ∈ p.byType.getD [], (q.1 = .rotate → p.threshold ≤ q.2) ∧
    (q.2 < p.threshold → q.1.lowType = true) ∧
    (q.1.prType = true → q.2 ≤ (ks.filter (fun k => !(p.agentCred ks k.cred))).length) ∧
    (p.att = true → q.1.prType = true → q.2 ≤ (ks.filter (fun k => p.started k.cred tset)).length)) ∧
  (∀ a ∈ p.attestations.getD [], p.agentCred ks a.subject.cred = false)

theorem valid_local_rules {s ks ds p t g} (h : policyValid s ks ds p t g = true) : LocalRules p ks t := by
  have pos := policy_positive h
  simp only [policyValid,Bool.and_eq_true,List.all_eq_true,decide_eq_true_eq,
    Bool.or_eq_true,Bool.not_eq_true,bne_iff_ne] at h
  unfold LocalRules
  grind

theorem reachable_local_rules {s : State} (hr : Reachable s) {p : Policy}
    (hp : s.epoch.policy = some p) : LocalRules p s.epoch.keys s.epoch.tset := by
  induction hr with
  | genesis g valid =>
    have ge : g.policy = some p := by simpa [initialState] using hp
    simp only [genesisValid,ge,Bool.and_eq_true] at valid
    simpa [initialState] using valid_local_rules valid.2
  | @step s e hr ha ih =>
    by_cases rot : e.body.tag = .rotate
    · have ep : e.body.policy = some p := by simpa [apply,rot] using hp
      have valid := accepted_resulting_policy ha rot
      simp only [resultingPolicyValid,ep] at valid
      simpa [apply,rot] using valid_local_rules valid
    · have old : s.epoch.policy = some p := by simpa [apply,rot] using hp
      simpa [apply,rot] using ih old

theorem mrot_above_threshold {p ks t} (h : LocalRules p ks t) : p.threshold ≤ p.mrot := by
  unfold Policy.mrot Policy.override
  cases hf : (p.byType.getD []).find? (fun q => q.1 == .rotate) with
  | none => simp
  | some q =>
    have mem := List.mem_of_find?_eq_some hf
    have tag : q.1 = .rotate := by simpa using List.find?_some hf
    simpa using (h.2.2.2.2.1 q mem).1 tag

theorem valid_implies_started (p : Policy) (c t : Nat) (h : p.validAt c t = true) : p.started c t = true := by
  unfold Policy.validAt at h
  cases hs : p.stmt c with
  | none => simp [hs] at h
  | some a =>
    simp only [hs,validAt,Bool.and_eq_true] at h
    simpa [Policy.started,hs] using h.1

theorem filter_length_mono (xs : List α) (p q : α → Bool)
    (h : ∀ x ∈ xs, p x = true → q x = true) : (xs.filter p).length ≤ (xs.filter q).length := by
  induction xs with
  | nil => simp
  | cons x xs ih =>
    have tail := ih (by intro y hy hp; exact h y (by simp [hy]) hp)
    have front := h x (by simp)
    cases hp : p x <;> cases hq : q x <;> simp_all <;> omega

theorem I32_started_bound {p ks tset} (h : LocalRules p ks tset) (att : p.att = true)
    (tag : Tag) (pr : tag.prType = true) :
    (p.override tag).getD p.threshold ≤ (ks.filter (fun k => p.started k.cred tset)).length := by
  cases ho : p.override tag with
  | none =>
    have rot := mrot_above_threshold h
    have valid := h.2.2.2.1 att
    have started := filter_length_mono ks (fun k => p.validAt k.cred tset)
      (fun k => p.started k.cred tset) (by intro k _ hk; exact valid_implies_started p k.cred tset hk)
    simp only [Option.getD_none]
    omega
  | some n =>
    unfold Policy.override at ho
    cases hf : (p.byType.getD []).find? (fun q => q.1 == tag) with
    | none => simp [hf] at ho
    | some q =>
      have mem := List.mem_of_find?_eq_some hf
      have tq : q.1 = tag := by simpa using List.find?_some hf
      have bound := (h.2.2.2.2.1 q mem).2.2.2 att (by simpa [tq] using pr)
      simp [hf] at ho
      simpa [ho] using bound

theorem I32_human_class_available {p ks tset} (h : LocalRules p ks tset)
    (att : p.att = true) (tag : Tag) (pr : tag.prType = true) (t : Nat) (future : tset ≤ t) :
    (p.override tag).getD p.threshold ≤ (ks.filter (fun k => (cls p ks t k.cred).humanClass)).length := by
  apply Nat.le_trans (I32_started_bound h att tag pr)
  apply filter_length_mono
  intro k _ started
  have nonAgent : p.agentCred ks k.cred = false := by
    unfold Policy.started at started
    cases hs : p.stmt k.cred with
    | none => simp [hs] at started
    | some a =>
      have mem := List.mem_of_find?_eq_some hs
      have cred : a.subject.cred = k.cred := by simpa [Policy.stmt] using List.find?_some hs
      simpa [cred] using h.2.2.2.2.2 a mem
  exact started_human_or_lapsed p ks k.cred tset t att started future nonAgent

theorem I32_nonreducing_threshold {s : State} (hr : Reachable s) (e : Event)
    (notpr : prEff s.records e.body e.time = false) (notcheckpoint : e.body.tag ≠ .checkpoint) :
    s.epoch.p.threshold ≤ meff s e := by
  cases hp : s.epoch.policy with
  | none => simp [meff,Epoch.p,hp,Policy.override]
  | some p =>
    have rules := reachable_local_rules hr hp
    have pe : s.epoch.p = p := by simp [Epoch.p,hp]
    unfold meff
    dsimp only
    rw [pe]
    cases ho : p.override e.body.tag with
    | none => simp
    | some n =>
      by_cases low : n < p.threshold
      · have allowed : e.body.tag.lowType = true := by
          unfold Policy.override at ho
          cases hf : (p.byType.getD []).find? (fun q => q.1 == e.body.tag) with
          | none => simp [hf] at ho
          | some q =>
            have mem := List.mem_of_find?_eq_some hf
            have tq : q.1 = e.body.tag := by simpa using List.find?_some hf
            simp [hf] at ho
            simpa [tq] using (rules.2.2.2.2.1 q mem).2.1 (by simpa [ho] using low)
        have ispr : e.body.tag.prType = true := by simpa [Tag.lowType,notcheckpoint] using allowed
        simp [ispr,low,notpr]
      · have hi : p.threshold ≤ n := by omega
        simp [low,hi]

/- Compatibility of the owner-authorization part with a separately written
   single-signature r4 reference. This is a reduced I20, not state-root equality. -/
def legacyAuthorization (s : State) (e : Event) : Bool := e.control.any (verifies s e)
theorem I20_default_authorization {s : State} {e : Event}
    (hp : s.epoch.policy = none) (he : e.body.policy = none) (ha : e.additional = none) :
    authorization s e = legacyAuthorization s e := by
  cases hc : e.control <;>
    simp [authorization,legacyAuthorization,signers,ha,hc,counting,counts,signerClass,cls,
      Epoch.p,hp,Policy.att,Policy.agentCred,meff,Policy.override,unique,Class.humanClass]

end IronTrellis
