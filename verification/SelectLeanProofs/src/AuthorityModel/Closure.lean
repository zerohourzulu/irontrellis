import AuthorityModel.Bounds
namespace Authority

/-- Least semantic dependency closure: all declared requirements of the main
    path, recursively all requirements of each eligible resolved partner. -/
inductive RequiredReachable (c : Corpus) (paths : List Path) (main : Path) (actor : Id) : Id → Prop where
  | main {id} : PathRequires main id → RequiredReachable c paths main actor id
  | partner {id p next} : RequiredReachable c paths main actor id →
      partnerFor c paths actor id = some p → PathRequires p next →
      RequiredReachable c paths main actor next

def Covered (seen : List Id) (queue : List Requirement) (id : Id) : Prop :=
  id ∈ seen ∨ ∃ req ∈ queue, req.requiredId = id

def Resolved (c : Corpus) (paths : List Path) (actor : Id) (graph : Graph) (id : Id) : Prop :=
  id ∈ graph.missing ∨ ∃ p ∈ graph.partners, partnerFor c paths actor id = some p

structure SelectionInvariant (c : Corpus) (paths : List Path) (main : Path) (actor : Id)
    (s : TraversalState) : Prop where
  main_eq : s.graph.main = main
  seen_resolved : ∀ id ∈ s.seen, Resolved c paths actor s.graph id
  obligations : ∀ p ∈ s.graph.paths, ∀ id, PathRequires p id → Covered s.seen s.queue id
  partner_sound : ∀ p ∈ s.graph.partners, ∃ id, RequiredReachable c paths main actor id ∧ partnerFor c paths actor id = some p
  missing_sound : ∀ id ∈ s.graph.missing, RequiredReachable c paths main actor id ∧ partnerFor c paths actor id = none
  queue_reachable : ∀ req ∈ s.queue, RequiredReachable c paths main actor req.requiredId

theorem covered_drop (seen : List Id) (req : Requirement) (queue : List Requirement) (id : Id)
    (hs : req.requiredId ∈ seen) (h : Covered seen (req::queue) id) : Covered seen queue id := by
  rcases h with h | ⟨r,hr,he⟩
  · exact Or.inl h
  · rcases List.mem_cons.mp hr with rfl | hr
    · exact Or.inl (he ▸ hs)
    · exact Or.inr ⟨r,hr,he⟩

theorem covered_process (seen : List Id) (req : Requirement) (queue extra : List Requirement) (id : Id)
    (h : Covered seen (req::queue) id) : Covered (req.requiredId::seen) (queue++extra) id := by
  rcases h with h | ⟨r,hr,he⟩
  · exact Or.inl (List.mem_cons_of_mem _ h)
  · rcases List.mem_cons.mp hr with rfl | hr
    · exact Or.inl (by simp [he])
    · exact Or.inr ⟨r,List.mem_append_left _ hr,he⟩

theorem resolved_mono (c : Corpus) (paths : List Path) (actor : Id) (g h : Graph)
    (hm : ∀ id ∈ g.missing, id ∈ h.missing) (hp : ∀ p ∈ g.partners, p ∈ h.partners)
    (id : Id) (hr : Resolved c paths actor g id) : Resolved c paths actor h id := by
  rcases hr with hr | ⟨p,hp',he⟩
  · exact Or.inl (hm id hr)
  · exact Or.inr ⟨p,hp p hp',he⟩

theorem selectionInvariant_initial (c : Corpus) (paths : List Path) (main : Path) (actor : Id) :
    SelectionInvariant c paths main actor ⟨[],directRequirements main,{ main := main }⟩ := by
  constructor
  · rfl
  · simp
  · intro p hp id hid
    simp only [Graph.paths,List.mem_cons,List.not_mem_nil,or_false] at hp
    subst p
    exact Or.inr ((direct_requirements_iff main id).mpr hid)
  · simp
  · simp
  · intro req hr
    exact RequiredReachable.main ((direct_requirements_iff main req.requiredId).mp ⟨req,hr,rfl⟩)

theorem selectionInvariant_step (c : Corpus) (paths : List Path) (main : Path) (actor : Id)
    (s : TraversalState) (inv : SelectionInvariant c paths main actor s) :
    SelectionInvariant c paths main actor (traversalStep c paths actor s) := by
  rcases s with ⟨seen,queue,graph⟩
  cases queue with
  | nil => exact inv
  | cons req queue =>
    have hreach := inv.queue_reachable req (by simp)
    simp only [traversalStep]
    cases hs : seen.contains req.requiredId
    · simp only [Bool.false_eq_true,↓reduceIte]
      cases hr : partnerFor c paths actor req.requiredId with
      | none =>
        constructor
        · exact inv.main_eq
        · intro id hi
          rcases List.mem_cons.mp hi with rfl | hi
          · exact Or.inl (by simp)
          · exact resolved_mono c paths actor graph _ (by intro x hx; simp [hx]) (by simp) id (inv.seen_resolved id hi)
        · intro p hp id hid
          have old := inv.obligations p hp id hid
          simpa only [List.append_nil] using covered_process seen req queue [] id old
        · exact inv.partner_sound
        · intro id hi
          rcases List.mem_cons.mp hi with rfl | hi
          · exact ⟨hreach,hr⟩
          · exact inv.missing_sound id hi
        · intro r h; exact inv.queue_reachable r (List.mem_cons_of_mem _ h)
      | some p =>
        constructor
        · exact inv.main_eq
        · intro id hi
          rcases List.mem_cons.mp hi with rfl | hi
          · exact Or.inr ⟨p,by simp,hr⟩
          · exact resolved_mono c paths actor graph _ (by simp) (by intro q hq; simp [hq]) id (inv.seen_resolved id hi)
        · intro q hq id hid
          simp only [Graph.paths,List.mem_cons,List.mem_append,List.not_mem_nil,or_false] at hq
          rcases hq with hmain | hold | hnew
          · exact covered_process seen req queue _ id (inv.obligations q (by simp [Graph.paths,hmain]) id hid)
          · exact covered_process seen req queue _ id (inv.obligations q (by simp [Graph.paths,hold]) id hid)
          · subst q
            obtain ⟨r,hm,he⟩ := (direct_requirements_iff p id).mpr hid
            exact Or.inr ⟨r,List.mem_append_right _ hm,he⟩
        · intro q hq
          rcases List.mem_append.mp hq with hold | hnew
          · exact inv.partner_sound q hold
          · have he := List.mem_singleton.mp hnew
            exact ⟨req.requiredId,hreach,by simpa [he] using hr⟩
        · exact inv.missing_sound
        · intro r hin
          rcases List.mem_append.mp hin with hold | hnew
          · exact inv.queue_reachable r (List.mem_cons_of_mem _ hold)
          · exact RequiredReachable.partner hreach hr ((direct_requirements_iff p r.requiredId).mp ⟨r,hnew,rfl⟩)
    · simp only [↓reduceIte]
      constructor
      · exact inv.main_eq
      · exact inv.seen_resolved
      · intro p hp id hid
        exact covered_drop seen req queue id (List.contains_iff_mem.mp hs) (inv.obligations p hp id hid)
      · exact inv.partner_sound
      · exact inv.missing_sound
      · intro r hr; exact inv.queue_reachable r (List.mem_cons_of_mem _ hr)

theorem selectionInvariant_traversal (c : Corpus) (paths : List Path) (main : Path) (actor : Id)
    (fuel : Nat) (s : TraversalState) (inv : SelectionInvariant c paths main actor s) :
    SelectionInvariant c paths main actor (traversal c paths actor fuel s) := by
  induction fuel generalizing s with
  | zero => exact inv
  | succ n ih =>
    cases hq : s.queue with
    | nil => simpa [traversal,hq] using inv
    | cons req queue => simpa only [traversal,hq] using ih _ (selectionInvariant_step _ _ _ _ s inv)


theorem drained_obligation_resolved (c : Corpus) (paths : List Path) (main : Path) (actor : Id)
    (s : TraversalState) (inv : SelectionInvariant c paths main actor s) (hq : s.queue = [])
    (p : Path) (hp : p ∈ s.graph.paths) (id : Id) (hid : PathRequires p id) :
    Resolved c paths actor s.graph id := by
  rcases inv.obligations p hp id hid with hseen | ⟨req,hr,_⟩
  · exact inv.seen_resolved id hseen
  · simp [hq] at hr

theorem drained_reachable_resolved (c : Corpus) (paths : List Path) (main : Path) (actor : Id)
    (s : TraversalState) (inv : SelectionInvariant c paths main actor s) (hq : s.queue = [])
    (id : Id) (hid : RequiredReachable c paths main actor id) : Resolved c paths actor s.graph id := by
  induction hid with
  | main h => exact drained_obligation_resolved _ _ _ _ _ inv hq main (by simp [Graph.paths,inv.main_eq]) _ h
  | @partner id p next hreach hr hreq ih =>
    rcases ih with hmissing | ⟨q,hq',he⟩
    · have hf := (inv.missing_sound id hmissing).2
      rw [hf] at hr; contradiction
    · have hsame : q = p := Option.some.inj (he.symm.trans hr)
      subst q
      exact drained_obligation_resolved _ _ _ _ _ inv hq p (by simp [Graph.paths,hq']) next hreq

theorem drained_exact (c : Corpus) (paths : List Path) (main : Path) (actor : Id)
    (s : TraversalState) (inv : SelectionInvariant c paths main actor s) (hq : s.queue = []) :
    (∀ p, p ∈ s.graph.partners ↔ ∃ id, RequiredReachable c paths main actor id ∧ partnerFor c paths actor id = some p) ∧
    (∀ id, id ∈ s.graph.missing ↔ RequiredReachable c paths main actor id ∧ partnerFor c paths actor id = none) := by
  constructor
  · intro p; constructor
    · exact inv.partner_sound p
    · rintro ⟨id,hreach,hr⟩
      rcases drained_reachable_resolved _ _ _ _ s inv hq id hreach with hm | ⟨q,hp,he⟩
      · have hf := (inv.missing_sound id hm).2
        rw [hf] at hr; contradiction
      · have heq : q = p := Option.some.inj (he.symm.trans hr)
        simpa [heq] using hp
  · intro id; constructor
    · exact inv.missing_sound id
    · rintro ⟨hreach,hr⟩
      rcases drained_reachable_resolved _ _ _ _ s inv hq id hreach with hm | ⟨q,hp,he⟩
      · exact hm
      · rw [hr] at he; contradiction

/-- No missing IDs implies an exhausted work queue even without typed bounds:
    the executable zero-fuel branch cannot silently return partial success. -/
theorem selectGraph_no_missing_drains (c : Corpus) (paths : List Path) (main : Path) (actor : Id)
    (h : (selectGraph c paths main actor).missing = []) :
    (traversal c paths actor ((c.permissions.length+1)*1024+1)
      ⟨[],directRequirements main,{ main := main }⟩).queue = [] := by
  unfold selectGraph at h
  rw [← traversal_refines_selectLoop] at h
  have hu := (sorted_eq_nil _).mp h
  have he : (finishTraversal (traversal c paths actor ((c.permissions.length+1)*1024+1)
      ⟨[],directRequirements main,{ main := main }⟩)).missing = [] := by
    apply List.eq_nil_iff_forall_not_mem.mpr
    intro id hid
    have hd : id ∈ (finishTraversal (traversal c paths actor ((c.permissions.length+1)*1024+1)
      ⟨[],directRequirements main,{ main := main }⟩)).missing.eraseDups := by simpa using hid
    simp [hu] at hd
  simp only [finishTraversal,List.append_eq_nil_iff,List.map_eq_nil_iff] at he
  exact he.2

theorem selectGraph_exact_of_drained (c : Corpus) (paths : List Path) (main : Path) (actor : Id)
    (hq : (traversal c paths actor ((c.permissions.length+1)*1024+1)
      ⟨[],directRequirements main,{ main := main }⟩).queue = []) :
    (∀ p, p ∈ (selectGraph c paths main actor).partners ↔ ∃ id, RequiredReachable c paths main actor id ∧ partnerFor c paths actor id = some p) ∧
    (∀ id, id ∈ (selectGraph c paths main actor).missing ↔ RequiredReachable c paths main actor id ∧ partnerFor c paths actor id = none) := by
  have inv := selectionInvariant_traversal c paths main actor ((c.permissions.length+1)*1024+1) _ (selectionInvariant_initial c paths main actor)
  have hex := drained_exact c paths main actor _ inv hq
  simp only [selectGraph,← traversal_refines_selectLoop,finishTraversal,hq,List.map_nil,List.append_nil,List.mem_mergeSort,mem_union_iff]
  exact hex

theorem selectGraph_semantically_complete (c : Corpus) (paths : List Path) (main : Path) (actor : Id)
    (hc : corpusStatus c = .valid) (hv : validateCorpus c = .ok paths) (hm : main ∈ paths) :
    (∀ p, p ∈ (selectGraph c paths main actor).partners ↔ ∃ id, RequiredReachable c paths main actor id ∧ partnerFor c paths actor id = some p) ∧
    (∀ id, id ∈ (selectGraph c paths main actor).missing ↔ RequiredReachable c paths main actor id ∧ partnerFor c paths actor id = none) :=
  selectGraph_exact_of_drained c paths main actor (selectGraph_fuel_sufficient c paths main actor hc hv hm)

#print axioms covered_drop
#print axioms covered_process
#print axioms resolved_mono
#print axioms selectionInvariant_initial
#print axioms selectionInvariant_step
#print axioms selectionInvariant_traversal
#print axioms drained_obligation_resolved
#print axioms drained_reachable_resolved
#print axioms drained_exact
#print axioms selectGraph_no_missing_drains
#print axioms selectGraph_exact_of_drained
#print axioms selectGraph_semantically_complete
end Authority
