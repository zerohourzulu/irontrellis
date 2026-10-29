import OwnerPolicy.IronTrellis.Liveness
import OwnerPolicy.IronTrellis.Structural
namespace IronTrellis

/- H-1 is ideal signature availability: a holder can form this signature.
   No verification premise is supplied: verification is proved below from
   deterministic key resolution and the key declaration test. -/
def makeSignature (s : State) (e : Event) (k : Key) : Signature :=
  {keyId := k.id,credential := k.cred,challenge := challenge s e,valid := true}

def withSignatures (s : State) (e : Event) (first : Key) (rest : List Key) : Event :=
  {e with
    control := some (makeSignature s e first),
    additional := if rest.isEmpty then none else some (rest.map (makeSignature s e))}

theorem signers_constructed (s : State) (e : Event) (k : Key) (ks : List Key) :
    signers (withSignatures s e k ks) = (k::ks).map (makeSignature s e) := by
  cases ks <;> simp [withSignatures,signers]

theorem constructed_verifies (s : State) (e : Event) (first : Key) (rest : List Key) (k : Key)
    (resolved : (adm s e).find? (fun x => x.id == k.id) = some k) (valid : k.valid = true) :
    verifies s (withSignatures s e first rest) (makeSignature s e k) = true := by
  have hadm : adm s (withSignatures s e first rest) = adm s e := rfl
  have hchallenge : challenge s (withSignatures s e first rest) = challenge s e := rfl
  simp [verifies,resolve,makeSignature,hadm,hchallenge,resolved,valid]

def Eligible (s : State) (e : Event) (k : Key) : Bool :=
  counts s.epoch.p.att (e.body.tag == .rotate) (isRestoration s e) (exempt s e)
    (cls s.epoch.p s.epoch.keys e.time k.cred)

theorem counting_constructed (s : State) (e : Event) (first : Key) (rest : List Key)
    (eligible : ∀ k ∈ first::rest, Eligible s e k = true) :
    counting s (withSignatures s e first rest) = (first::rest).map (makeSignature s e) := by
  unfold counting
  rw [signers_constructed]
  apply List.filter_eq_self.mpr
  intro sig hs
  obtain ⟨k,hk,rfl⟩ := List.mem_map.mp hs
  exact eligible k hk

structure ChosenKeys (s : State) (e : Event) (first : Key) (rest : List Key) : Prop where
  resolved : ∀ k ∈ first::rest, (adm s e).find? (fun x => x.id == k.id) = some k
  valid : ∀ k ∈ first::rest, k.valid = true
  ids : unique ((first::rest).map (·.id)) = true
  credentials : unique ((first::rest).map (·.cred)) = true
  number : (first::rest).length = meff s e
  eligible : ∀ k ∈ first::rest, Eligible s e k = true
  human : (cls s.epoch.p s.epoch.keys e.time first.cred).humanClass = true

theorem authorization_constructed (s : State) (e : Event) (first : Key) (rest : List Key)
    (choice : ChosenKeys s e first rest) : authorization s (withSignatures s e first rest) = true := by
  have heff : meff s (withSignatures s e first rest) = meff s e := rfl
  have presence : (withSignatures s e first rest).additional.isSome = decide (2 ≤ meff s e) := by
    have number := choice.number
    cases rest <;> simp_all [withSignatures] <;> omega
  have allVerified : (signers (withSignatures s e first rest)).all
      (verifies s (withSignatures s e first rest)) = true := by
    rw [signers_constructed]
    simp only [List.all_eq_true,List.mem_map,forall_exists_index,and_imp]
    intro sig k hk heq
    subst sig
    exact constructed_verifies s e first rest k (choice.resolved k hk) (choice.valid k hk)
  have hcount := counting_constructed s e first rest choice.eligible
  have ids : unique ((signers (withSignatures s e first rest)).map (·.keyId)) = true := by
    simpa [signers_constructed,List.map_map,Function.comp_def,makeSignature] using choice.ids
  have creds : unique ((signers (withSignatures s e first rest)).map (·.credential)) = true := by
    simpa [signers_constructed,List.map_map,Function.comp_def,makeSignature] using choice.credentials
  have someHuman : (counting s (withSignatures s e first rest)).any
      (fun sig => (signerClass s (withSignatures s e first rest) sig).humanClass) = true := by
    rw [hcount]
    simp only [List.any_eq_true]
    exact ⟨makeSignature s e first,by simp,choice.human⟩
  simp only [authorization,heff,allVerified,presence,beq_self_eq_true,ids,creds,hcount,List.length_map,
    choice.number,Nat.le_refl,decide_true,Bool.and_true]
  rw [← hcount,someHuman]
  simp [withSignatures]

/- These establish eligibility from the actual L1/L2/L3/L5/L6/L8 classes.
   Selecting an exact distinct quorum from an arbitrary holder set, and
   discharging every H0 schema/transition condition, remain separate. -/
theorem L1_L4_declared_eligible (s : State) (e : Event) (k : Key)
    (declared : s.epoch.p.att = false) (nonrot : e.body.tag ≠ .rotate) : Eligible s e k = true := by
  simp [Eligible,counts,declared,nonrot]

theorem L2_ordinary_eligible (s : State) (e : Event) (k : Key)
    (nonrot : e.body.tag ≠ .rotate)
    (humanOrAgent : cls s.epoch.p s.epoch.keys e.time k.cred = .human ∨
      cls s.epoch.p s.epoch.keys e.time k.cred = .agent) : Eligible s e k = true := by
  rcases humanOrAgent with hc | hc <;>
    cases hat : s.epoch.p.att <;> cases hex : exempt s e <;> simp [Eligible,counts,nonrot,hc,hat,hex]

theorem L3_L11_exempt_eligible (s : State) (e : Event) (k : Key)
    (nonrot : e.body.tag ≠ .rotate) (ex : exempt s e = true)
    (qualified : cls s.epoch.p s.epoch.keys e.time k.cred ≠ .none) : Eligible s e k = true := by
  cases hat : s.epoch.p.att <;> simp [Eligible,counts,nonrot,hat,ex,qualified]

theorem L5_restoration_eligible (s : State) (e : Event) (k : Key)
    (restoration : isRestoration s e = true)
    (hc : (cls s.epoch.p s.epoch.keys e.time k.cred).humanClass = true) : Eligible s e k = true := by
  have rot : e.body.tag = .rotate := by
    unfold isRestoration isPolicyRot at restoration
    simp only [Bool.and_eq_true,beq_iff_eq] at restoration
    grind
  cases h : cls s.epoch.p s.epoch.keys e.time k.cred <;>
    simp_all [Eligible,counts,Class.humanClass]

theorem L6_L7_L8_rotation_eligible (s : State) (e : Event) (k : Key)
    (hc : cls s.epoch.p s.epoch.keys e.time k.cred = .human) : Eligible s e k = true := by
  cases hat : s.epoch.p.att <;> cases hr : e.body.tag == .rotate <;>
    cases hrest : isRestoration s e <;> cases hx : exempt s e <;>
    simp [Eligible,counts,hat,hr,hrest,hx,hc,Class.humanClass]

/- Full impossibility in the main ideal-signature model. No owned admitted
   human-class key and no owned committed credential can produce an accepted
   control event. Quantifying this premise over all future t yields L10's
   owner-event clause; runtime continuation remains outside this theorem. -/
theorem L10_no_owner_event {s : State} {e : Event} {held : List Cred}
    (control : e.body.tag.control = true) (uses : UsesOnly e held)
    (noCurrent : ∀ k ∈ s.epoch.keys, k.cred ∈ held →
      (cls s.epoch.p s.epoch.keys e.time k.cred).humanClass = false)
    (noEscrow : s.epoch.p.recovery = false ∨ ∀ c ∈ s.epoch.d, c ∉ held) : ¬ Accepted s e := by
  intro accepted
  have fields := authorization_fields (accepted_authorization accepted control)
  obtain ⟨sig,hcount,hclass⟩ := fields.2.2.2.2.2.2
  have hs : sig ∈ signers e := (List.mem_filter.mp hcount).1
  obtain ⟨k,_,hadm,_,hcred,_⟩ := verifies_resolved (fields.2.1 sig hs)
  have hheld : k.cred ∈ held := hcred ▸ uses sig hs
  have hcurrent : k ∈ s.epoch.keys := by
    simp only [adm,List.mem_append] at hadm
    rcases hadm with current | revealed
    · exact current
    · rcases noEscrow with disabled | unavailable
      · simp [disabled] at revealed
      · split at revealed
        · have hd := (List.mem_filter.mp revealed).2
          have hdmem := List.contains_iff_mem.mp hd
          exact False.elim (unavailable k.cred hdmem hheld)
        · simp at revealed
  have hn := noCurrent k hcurrent hheld
  simpa [signerClass,hcred,hn] using hclass


/- Explicit H0 obligations, with no authorization or acceptance premise.
   The event here is the actual constructed event, so closed-schema/presence
   side conditions cannot be silently borrowed from a different template. -/
structure H0Remaining (s : State) (e : Event) : Prop where
  schema : eventSchema e = true
  policyShape : e.body.policy.all policyShape = true
  additionalShape : optionalListShape e.additional 63 = true
  nextShape : optionalListShape e.next 64 = true
  u53 : e.time ≤ MAXT
  native : e.inPrefix = false
  monotonic : s.time ≤ e.time
  owner : e.body.tag.control = true
  keyTest : e.body.tag = .rotate → (keyShape e.body.ownerKeys && digestShape e.body.digests && foreignOwnerOK s e) = true
  policyTest : e.body.tag = .rotate → resultingPolicyValid s e = true
  transition : transitionOK s e = true
  capacity : e.capacityOK = true

theorem authorizable_from_chosen_keys (s : State) (template : Event) (first : Key) (rest : List Key)
    (chosen : ChosenKeys s template first rest)
    (side : H0Remaining s (withSignatures s template first rest))
    (clock : t2 s (withSignatures s template first rest) = true) :
    ∃ e, e = withSignatures s template first rest ∧ Accepted s e := by
  refine ⟨withSignatures s template first rest,rfl,construction_accepts ?_⟩
  exact ⟨side.schema,side.policyShape,side.additionalShape,side.nextShape,side.u53,side.native,
    side.monotonic,side.owner,authorization_constructed s template first rest chosen,clock,
    side.keyTest,side.policyTest,side.transition,side.capacity⟩

theorem L11_chosen_checkpoint_at_head (s : State) (template : Event) (first : Key) (rest : List Key)
    (_checkpoint : template.body.tag = .checkpoint) (atHead : template.time = s.time)
    (chosen : ChosenKeys s template first rest)
    (side : H0Remaining s (withSignatures s template first rest)) :
    ∃ e, e = withSignatures s template first rest ∧ Accepted s e :=
  authorizable_from_chosen_keys s template first rest chosen side
    (T2_at_head s _ atHead)

theorem L3_corrected_chosen_within_horizon (s : State) (template : Event) (first : Key) (rest : List Key)
    (_reduction : prEff s.records template.body template.time = true ∨ template.body.tag = .checkpoint)
    (horizon : template.time ≤ min s.epoch.p.horizon (MAXT-1))
    (chosen : ChosenKeys s template first rest)
    (side : H0Remaining s (withSignatures s template first rest)) :
    ∃ e, e = withSignatures s template first rest ∧ Accepted s e :=
  authorizable_from_chosen_keys s template first rest chosen side
    (T2_single_within_horizon s _ horizon)

theorem L1_L4_chosen_declared (s : State) (template : Event) (first : Key) (rest : List Key)
    (declared : s.epoch.p.att = false) (chosen : ChosenKeys s template first rest)
    (side : H0Remaining s (withSignatures s template first rest)) :
    ∃ e, e = withSignatures s template first rest ∧ Accepted s e :=
  authorizable_from_chosen_keys s template first rest chosen side (by simp [t2,declared])

end IronTrellis
