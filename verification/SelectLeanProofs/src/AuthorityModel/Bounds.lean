import AuthorityModel.Fuel
namespace Authority

theorem merge_valid_iff (a b : Validity) : merge a b = .valid ↔ a = .valid ∧ b = .valid := by
  cases a <;> cases b <;> decide

theorem statuses_valid (xs : List Validity) (initial : Validity)
    (h : xs.foldl merge initial = .valid) : initial = .valid ∧ ∀ x ∈ xs, x = .valid := by
  induction xs generalizing initial with
  | nil => exact ⟨h, by simp⟩
  | cons x xs ih =>
    obtain ⟨hm,hr⟩ := ih (merge initial x) h
    obtain ⟨hi,hx⟩ := (merge_valid_iff _ _).mp hm
    exact ⟨hi, by intro y hy; rcases List.mem_cons.mp hy with rfl | hy; exact hx; exact hr y hy⟩

theorem corpus_permission_status (c : Corpus) (h : corpusStatus c = .valid)
    (g : Permission) (hg : g ∈ c.permissions) : permissionStatus g = .valid := by
  unfold corpusStatus at h
  have hs := (statuses_valid _ _ h).2
  apply hs
  simp only [List.mem_append, List.mem_map]
  exact Or.inl (Or.inl (Or.inl (Or.inl (Or.inl ⟨g,hg,rfl⟩))))

theorem permission_requirement_bound (g : Permission) (h : permissionStatus g = .valid) :
    g.constraints.requiredIntersectionIds.length ≤ 32 := by
  have hc : constraintsStatus g.constraints = .valid := (statuses_valid _ _ h).2 _ (by simp)
  have hi : idsStatus g.constraints.requiredIntersectionIds 32 = .valid := (statuses_valid _ _ hc).2 _ (by simp)
  unfold idsStatus at hi
  have hp := ((merge_valid_iff _ _).mp hi).2
  by_cases hn : g.constraints.requiredIntersectionIds.length ≤ 32
  · exact hn
  · have ht : g.constraints.requiredIntersectionIds.length > 32 := by omega
    simp [ht] at hp

theorem buildUp_shape (c : Corpus) (fuel : Nat) (seen : List Id) (g : Permission) (gs : List Permission)
    (hg : g ∈ c.permissions) (h : buildUp c fuel seen g = .ok gs) :
    gs.length ≤ fuel ∧ ∀ grant ∈ gs, grant ∈ c.permissions := by
  induction fuel generalizing seen g gs with
  | zero => simp [buildUp] at h
  | succ n ih =>
    simp only [buildUp] at h
    split at h
    · contradiction
    · cases hp : g.parentAuthorityId with
      | none =>
        simp [hp] at h; cases h
        exact ⟨by simp, by simpa using hg⟩
      | some id =>
        simp only [hp] at h
        cases hf : permission c id with
        | none => simp [hf] at h
        | some parent =>
          cases ha : buildUp c n (g.authorityId::seen) parent with
          | error e => simp [hf,ha,bind,Except.bind] at h
          | ok ancestors =>
            simp [hf,ha,bind,Except.bind,pure] at h
            cases h
            have hparent : parent ∈ c.permissions := List.mem_of_find?_eq_some hf
            obtain ⟨hl,hm⟩ := ih _ _ _ hparent ha
            constructor
            · simp only [List.length_append,List.length_singleton]; omega
            · intro grant hin
              rcases List.mem_append.mp hin with hin | hin
              · exact hm grant hin
              · simpa using (List.mem_singleton.mp hin) ▸ hg

theorem buildPath_shape (c : Corpus) (g : Permission) (p : Path)
    (hg : g ∈ c.permissions) (h : buildPath c g = .ok p) :
    p.grants.length ≤ 32 ∧ ∀ grant ∈ p.grants, grant ∈ c.permissions := by
  unfold buildPath at h
  cases hs : buildUp c 32 [] g with
  | error e => simp [hs,bind,Except.bind] at h
  | ok gs =>
    simp only [hs,bind,Except.bind,pure] at h
    split at h
    · cases h; exact buildUp_shape c 32 [] g gs hg hs
    · contradiction

theorem mapM_buildPath_shape (c : Corpus) (gs : List Permission) (ps : List Path)
    (members : ∀ g ∈ gs, g ∈ c.permissions) (h : gs.mapM (buildPath c) = .ok ps) :
    ps.length = gs.length ∧ ∀ p ∈ ps, p.grants.length ≤ 32 ∧ ∀ grant ∈ p.grants, grant ∈ c.permissions := by
  induction gs generalizing ps with
  | nil => simp at h; cases h; simp
  | cons g gs ih =>
    simp only [List.mapM_cons] at h
    cases hg : buildPath c g with
    | error e => simp [hg,bind,Except.bind] at h
    | ok path =>
      cases hs : gs.mapM (buildPath c) with
      | error e => simp [hg,hs,bind,Except.bind] at h
      | ok rest =>
        simp [hg,hs,bind,Except.bind] at h; cases h
        obtain ⟨hl,hm⟩ := ih rest (fun q hq => members q (by simp [hq])) hs
        constructor
        · simp [hl]
        · intro p hp
          rcases List.mem_cons.mp hp with rfl | hp
          · exact buildPath_shape c g p (members g (by simp)) hg
          · exact hm p hp

theorem validateCorpus_shape (c : Corpus) (paths : List Path) (h : validateCorpus c = .ok paths) :
    paths.length = c.permissions.length ∧
    ∀ p ∈ paths, p.grants.length ≤ 32 ∧ ∀ grant ∈ p.grants, grant ∈ c.permissions := by
  unfold validateCorpus at h
  cases hs : c.permissions.mapM (buildPath c) with
  | error e => simp [hs,bind,Except.bind] at h
  | ok ps =>
    simp only [hs,bind,Except.bind] at h
    split at h
    · contradiction
    · split at h
      · cases h; exact mapM_buildPath_shape _ _ _ (fun _ h => h) hs
      · contradiction

theorem direct_aux_length_bound (gs : List Permission) (previous : List Id)
    (h : ∀ g ∈ gs, g.constraints.requiredIntersectionIds.length ≤ 32) :
    (directRequirementsAux previous gs).length ≤ gs.length * 32 := by
  induction gs generalizing previous with
  | nil => simp [directRequirementsAux]
  | cons g gs ih =>
    have hg := h g (by simp)
    have hr := ih g.constraints.requiredIntersectionIds (fun p hp => h p (by simp [hp]))
    have hf := List.length_filter_le (fun id => !previous.contains id) g.constraints.requiredIntersectionIds
    simp only [directRequirementsAux,List.length_append,List.length_map,List.length_cons]
    omega

theorem validated_requirement_bound (c : Corpus) (paths : List Path)
    (hc : corpusStatus c = .valid) (hv : validateCorpus c = .ok paths) (p : Path) (hp : p ∈ paths) :
    (directRequirements p).length ≤ 1024 := by
  obtain ⟨_,hshape⟩ := validateCorpus_shape c paths hv
  obtain ⟨hdepth,hm⟩ := hshape p hp
  have hb := direct_aux_length_bound p.grants [] (fun g hg => permission_requirement_bound g (corpus_permission_status c hc g (hm g hg)))
  dsimp only [directRequirements]
  omega

theorem pendingCost_bound (paths : List Path) (seen : List Id) (bound : Nat)
    (h : ∀ p ∈ paths, (directRequirements p).length ≤ bound) :
    pendingCost paths seen ≤ paths.length * bound := by
  induction paths with
  | nil => simp [pendingCost]
  | cons p ps ih =>
    have hp := h p (by simp)
    have hr := ih (fun q hq => h q (by simp [hq]))
    simp only [pendingCost,List.length_cons]
    split <;> simp only [Nat.add_mul, Nat.one_mul] <;> omega

/-- The exact existing selectGraph constant suffices for every validated input;
    repeated queue entries are charged, and cycles require no extra premise. -/
theorem selectGraph_fuel_sufficient (c : Corpus) (paths : List Path) (main : Path) (actor : Id)
    (hc : corpusStatus c = .valid) (hv : validateCorpus c = .ok paths) (hm : main ∈ paths) :
    (traversal c paths actor ((c.permissions.length+1)*1024+1)
      ⟨[], directRequirements main, { main := main }⟩).queue = [] := by
  apply traversal_drains
  have hall := validated_requirement_bound c paths hc hv
  have hmain := hall main hm
  have hpaths := pendingCost_bound paths [] 1024 hall
  have hlen := (validateCorpus_shape c paths hv).1
  simp only [traversalCost]
  rw [hlen] at hpaths
  omega

#print axioms merge_valid_iff
#print axioms statuses_valid
#print axioms corpus_permission_status
#print axioms permission_requirement_bound
#print axioms buildUp_shape
#print axioms buildPath_shape
#print axioms mapM_buildPath_shape
#print axioms validateCorpus_shape
#print axioms direct_aux_length_bound
#print axioms validated_requirement_bound
#print axioms pendingCost_bound
#print axioms selectGraph_fuel_sufficient
end Authority
