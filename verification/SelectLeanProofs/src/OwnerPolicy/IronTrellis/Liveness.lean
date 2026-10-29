import OwnerPolicy.IronTrellis.Safety
import OwnerPolicy.IronTrellis.Counterexamples
namespace IronTrellis

def UsesOnly (e : Event) (held : List Cred) : Prop :=
  ∀ sig ∈ signers e, sig.credential ∈ held

theorem unique_singleton_length {xs : List Nat} {c : Nat}
    (hu : unique xs = true) (hall : ∀ x ∈ xs, x = c) : xs.length ≤ 1 := by
  cases xs with
  | nil => simp
  | cons a xs =>
    cases xs with
    | nil => simp
    | cons b bs =>
      have ha : a = c := hall a (by simp)
      have hb : b = c := hall b (by simp)
      simp [unique,ha,hb] at hu

theorem accepted_single_holder_count {s : State} {e : Event} (h : Accepted s e)
    (ctl : e.body.tag.control = true) (c : Cred) (held : UsesOnly e [c]) : hc s e ≤ 1 := by
  have hu := (I06_distinct h ctl).2
  have len : ((signers e).map (·.credential)).length ≤ 1 := by
    apply unique_singleton_length hu
    intro x hx
    obtain ⟨sig, hm, he⟩ := List.mem_map.mp hx
    have hc := held sig hm
    simp only [List.mem_singleton] at hc
    exact he ▸ hc
  have sigbound : (signers e).length ≤ 1 := by simpa using len
  exact Nat.le_trans (List.length_filter_le _ _) (Nat.le_trans (List.length_filter_le _ _) sigbound)

namespace Examples

theorem L3_no_checkpoint_at_11 :
    ¬∃ e : Event, e.body.tag = .checkpoint ∧ e.time = 11 ∧ Accepted base e := by
  rintro ⟨e, tag, et, h⟩
  have ctl : e.body.tag.control = true := by simp [tag,Tag.control]
  have m1 : meff base e = 1 := by
    simp [meff,tag,base,initialState,genesis,Epoch.p,strictPolicy,Policy.override,Tag.prType]
  have bound := I42_single_human_horizon h ctl (by decide) (I42_m1_count_bound h ctl m1)
  have horizon : base.epoch.p.horizon = 10 := by decide
  have head : base.time = 0 := by decide
  simp only [horizon,head,et] at bound
  omega

theorem L12_no_checkpoint_at_MAXT :
    ¬∃ e : Event, e.body.tag = .checkpoint ∧ e.time = MAXT ∧ Accepted maxBase e := by
  rintro ⟨e, tag, et, h⟩
  have ctl : e.body.tag.control = true := by simp [tag,Tag.control]
  have m1 : meff maxBase e = 1 := by
    simp [meff,tag,maxBase,initialState,genesis,Epoch.p,strictPolicy,Policy.override,Tag.prType]
  have bound := I42_single_human_horizon h ctl (by decide) (I42_m1_count_bound h ctl m1)
  have horizon : maxBase.epoch.p.horizon = MAXT := by decide
  have head : maxBase.time = 0 := by decide
  simp only [horizon,head,et,MAXT] at bound
  omega

theorem L12_no_owner_event_at_MAXT_with_one_holder :
    ¬∃ e : Event, e.body.tag.control = true ∧ e.time = MAXT ∧ UsesOnly e [1] ∧ Accepted maxBase e := by
  rintro ⟨e, ctl, et, held, h⟩
  have bound := I42_single_human_horizon h ctl (by decide) (accepted_single_holder_count h ctl 1 held)
  have horizon : maxBase.epoch.p.horizon = MAXT := by decide
  have head : maxBase.time = 0 := by decide
  simp only [horizon,head,et,MAXT] at bound
  omega

end Examples

/- This corrected time statement follows T1 for a fixed pre-event epoch. It
   makes no claim about an expiry removed or renewed by an intervening rotation. -/
theorem L12_fixed_epoch_necessity {s : State} {e : Event} (ha : Accepted s e)
    (att : s.epoch.p.att = true) (a : Attestation)
    (mem : a ∈ s.epoch.p.attestations.getD []) (future : s.time < a.expiresAt)
    (cross : a.expiresAt ≤ e.time) : e.body.tag.control = true :=
  I33_only_owners_cross ha att a mem future cross

/- The following two theorems isolate what the time rules actually guarantee,
   independently of cryptographic construction or r4 transition preconditions. -/
theorem T2_at_head (s : State) (e : Event) (ht : e.time = s.time) : t2 s e = true := by
  simp [t2,ht]
theorem T2_two_counting_humans (s : State) (e : Event) (h : 2 ≤ hc s e) : t2 s e = true := by
  simp [t2,show hc s e > 1 by omega]
theorem T2_single_within_horizon (s : State) (e : Event)
    (h : e.time ≤ min s.epoch.p.horizon (MAXT-1)) : t2 s e = true := by simp [t2,h]

/- H0's type-specific conditions and well-formed event are genuinely separate
   from counting. This construction lemma is NOT reported as proving L1–L11:
   it is a validation interface for their unresolved full existence proofs. -/
structure OwnerConstruction (s : State) (e : Event) : Prop where
  schema : eventSchema e = true
  policyShape : e.body.policy.all policyShape = true
  additionalShape : optionalListShape e.additional 63 = true
  nextShape : optionalListShape e.next 64 = true
  u53 : e.time ≤ MAXT
  native : e.inPrefix = false
  monotonic : s.time ≤ e.time
  owner : e.body.tag.control = true
  signed : authorization s e = true
  clock : t2 s e = true
  keyTest : e.body.tag = .rotate → (keyShape e.body.ownerKeys && digestShape e.body.digests && foreignOwnerOK s e) = true
  policyTest : e.body.tag = .rotate → resultingPolicyValid s e = true
  transition : transitionOK s e = true
  capacity : e.capacityOK = true

theorem construction_accepts {s : State} {e : Event} (h : OwnerConstruction s e) : Accepted s e := by
  simp only [Accepted,verdict,firstFailure_none]
  intro gate hg
  have h1 : t1 s e = true := by simp [t1,h.owner]
  simp [checks,h.schema,h.policyShape,h.additionalShape,h.nextShape,h.u53,h.native,
    h.monotonic,h.owner,h.signed,h.clock,h1,h.transition,h.capacity] at hg
  by_cases rot : e.body.tag = .rotate
  · simp [rot,h.keyTest rot,h.policyTest rot] at hg
    grind
  · simp [rot] at hg
    grind

end IronTrellis
