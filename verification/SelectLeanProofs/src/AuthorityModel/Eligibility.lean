import AuthorityModel.Closure
namespace Authority

/-- A declarative eligible authority: the named corpus record has a valid path,
    a recognized root, at least one dependent link, and the requested actor. -/
def EligiblePartner (c : Corpus) (actor id : Id) (p : Path) : Prop :=
  ∃ grant, permission c id = some grant ∧ buildPath c grant = .ok p ∧
    (∃ root, recognize c p = some root) ∧ p.independent = false ∧ p.terminal.granteeId = actor

theorem buildUp_terminal (c : Corpus) (fuel : Nat) (seen : List Id) (g : Permission) (gs : List Permission)
    (h : buildUp c fuel seen g = .ok gs) : gs.getLastD {} = g := by
  cases fuel with
  | zero => simp [buildUp] at h
  | succ n =>
    simp only [buildUp] at h
    split at h
    · contradiction
    · cases hp : g.parentAuthorityId with
      | none => simp [hp] at h; cases h; rfl
      | some id =>
        simp only [hp] at h
        cases hf : permission c id with
        | none => simp [hf] at h
        | some parent =>
          cases ha : buildUp c n (g.authorityId::seen) parent with
          | error e => simp [hf,ha,bind,Except.bind] at h
          | ok ancestors =>
            simp [hf,ha,bind,Except.bind,pure] at h; cases h
            simp

theorem buildPath_terminal (c : Corpus) (g : Permission) (p : Path)
    (h : buildPath c g = .ok p) : p.terminal = g := by
  unfold buildPath at h
  cases hs : buildUp c 32 [] g with
  | error e => simp [hs,bind,Except.bind] at h
  | ok gs =>
    simp only [hs,bind,Except.bind,pure] at h
    split at h
    · cases h; exact buildUp_terminal c 32 [] g gs hs
    · contradiction

theorem mapM_find_buildPath (c : Corpus) (gs : List Permission) (ps : List Path) (id : Id)
    (h : gs.mapM (buildPath c) = .ok ps) :
    ps.find? (fun p => p.terminal.authorityId == id) =
      (gs.find? (fun g => g.authorityId == id)).bind (fun g => match buildPath c g with | .ok p => some p | .error _ => none) := by
  induction gs generalizing ps with
  | nil => simp at h; cases h; rfl
  | cons g gs ih =>
    simp only [List.mapM_cons] at h
    cases hg : buildPath c g with
    | error e => simp [hg,bind,Except.bind] at h
    | ok path =>
      cases hs : gs.mapM (buildPath c) with
      | error e => simp [hg,hs,bind,Except.bind] at h
      | ok rest =>
        simp [hg,hs,bind,Except.bind] at h; cases h
        have ht := buildPath_terminal c g path hg
        simp only [List.find?_cons,ht]
        cases hi : g.authorityId == id <;> simp [hg,ih rest hs]

theorem validated_paths_mapM (c : Corpus) (paths : List Path) (h : validateCorpus c = .ok paths) :
    c.permissions.mapM (buildPath c) = .ok paths := by
  unfold validateCorpus at h
  cases hs : c.permissions.mapM (buildPath c) with
  | error e => simp [hs,bind,Except.bind] at h
  | ok ps =>
    simp only [hs,bind,Except.bind] at h
    split at h
    · contradiction
    · split at h
      · cases h; rfl
      · contradiction

theorem validated_find_iff (c : Corpus) (paths : List Path) (hv : validateCorpus c = .ok paths) (id : Id) (p : Path) :
    paths.find? (fun q => q.terminal.authorityId == id) = some p ↔
      ∃ g, permission c id = some g ∧ buildPath c g = .ok p := by
  rw [mapM_find_buildPath c c.permissions paths id (validated_paths_mapM c paths hv)]
  change (permission c id).bind _ = some p ↔ _
  cases hg : permission c id with
  | none => simp
  | some g =>
    cases hp : buildPath c g with
    | error e => simp [hp]
    | ok q => simp [hp]

/-- Eligibility is proved equivalent to the executable resolver from the
    separately validated corpus/path relation, rather than assumed. -/
theorem partnerFor_iff_eligible (c : Corpus) (paths : List Path) (hv : validateCorpus c = .ok paths)
    (actor id : Id) (p : Path) : partnerFor c paths actor id = some p ↔ EligiblePartner c actor id p := by
  constructor
  · intro h
    unfold partnerFor at h
    cases hf : paths.find? (fun q => q.terminal.authorityId == id) with
    | none => simp [hf] at h
    | some q =>
      simp only [hf] at h
      split at h
      · contradiction
      · rename_i hc
        cases h
        obtain ⟨g,hg,hp⟩ := (validated_find_iff c paths hv id p).mp hf
        cases hr : recognize c p with
        | none => simp [hr] at hc
        | some root =>
          refine ⟨g,hg,hp,⟨root,hr⟩,?_,?_⟩
          · cases hi : p.independent <;> simp_all
          · by_cases ha : p.terminal.granteeId = actor
            · exact ha
            · simp [hr,ha] at hc
  · rintro ⟨g,hg,hp,⟨root,hr⟩,hi,ha⟩
    have hf := (validated_find_iff c paths hv id p).mpr ⟨g,hg,hp⟩
    simp [partnerFor,hf,hr,hi,ha]

/-- Least transitive closure stated entirely using declared requirements and
    the corpus/path eligibility relation. It does not reference selectGraph. -/
inductive SemanticRequired (c : Corpus) (main : Path) (actor : Id) : Id → Prop where
  | main {id} : PathRequires main id → SemanticRequired c main actor id
  | partner {id p next} : SemanticRequired c main actor id → EligiblePartner c actor id p →
      PathRequires p next → SemanticRequired c main actor next

theorem reachable_iff_semantic (c : Corpus) (paths : List Path) (hv : validateCorpus c = .ok paths)
    (main : Path) (actor id : Id) : RequiredReachable c paths main actor id ↔ SemanticRequired c main actor id := by
  constructor
  · intro h; induction h with
    | main h => exact SemanticRequired.main h
    | partner _ hp hn ih => exact SemanticRequired.partner ih ((partnerFor_iff_eligible c paths hv _ _ _).mp hp) hn
  · intro h; induction h with
    | main h => exact RequiredReachable.main h
    | partner _ hp hn ih => exact RequiredReachable.partner ih ((partnerFor_iff_eligible c paths hv _ _ _).mpr hp) hn

#print axioms buildUp_terminal
#print axioms buildPath_terminal
#print axioms mapM_find_buildPath
#print axioms validated_paths_mapM
#print axioms validated_find_iff
#print axioms partnerFor_iff_eligible
#print axioms reachable_iff_semantic
end Authority
