import G65.Projection
import G65.RevocationDistinct

/- A-199: revocation over the procedure model. This additive module retains
   the exact architect-selected definitions and derives its preservation facts
   rather than admitting them as hypotheses. -/
namespace Authority.G64

def revoke (c : Corpus) (id : Id) : Corpus := { c with revoked := id :: c.revoked }

def prohibitionAnchors (paths : List Path) (p : Prohibition) (id : Id) : Bool :=
  (anchorPath paths p).any (fun path => path.ids.contains id)

def revocationGuard (c : Corpus) (paths : List Path) (id : Id) : Bool :=
  (permission c id).isSome && !c.revoked.contains id &&
  !c.prohibitions.any (fun p => !c.revoked.contains p.authorityId && prohibitionAnchors paths p id)

theorem buildUp_revoked (c : Corpus) (target : Id) (fuel : Nat) (seen : List Id) (g : Permission) :
    buildUp (revoke c target) fuel seen g = buildUp c fuel seen g := by
  induction fuel generalizing seen g with
  | zero => rfl
  | succ fuel ih =>
    simp only [buildUp, permission, revoke]
    split
    · rfl
    · split
      · rfl
      · split
        · rfl
        · simpa only [revoke] using congrArg
            (fun x : Except Code (List Permission) => (do let ancestors ← x; pure (ancestors ++ [g])))
            (ih (g.authorityId :: seen) _)

theorem buildPath_revoked (c : Corpus) (target : Id) (g : Permission) :
    buildPath (revoke c target) g = buildPath c g := by
  simp only [buildPath, buildUp_revoked]

/-- The validator also checks that every revoked identifier names an authority.
    The permission-existence conjunct of the normative guard establishes this
    for the added identifier; unconditional validation equality would be false. -/
theorem validation_revoked (c : Corpus) (paths : List Path) (target : Id)
    (guard : revocationGuard c paths target = true) :
    validateCorpus (revoke c target) = validateCorpus c := by
  have existsPermission : (permission c target).isSome = true := by
    have parts := guard
    simp only [revocationGuard, Bool.and_eq_true] at parts
    exact parts.1.1
  cases found : permission c target with
  | none => simp [found] at existsPermission
  | some g =>
    have member : g ∈ c.permissions := List.mem_of_find?_eq_some found
    have key : g.authorityId = target := by simpa using List.find?_some found
    have contains : (c.permissions.map (·.authorityId) ++ c.prohibitions.map (·.authorityId)).contains target = true := by
      simp only [List.contains_iff_mem, List.mem_append, List.mem_map]
      exact Or.inl ⟨g, member, key⟩
    have subsetEq : subset (target :: c.revoked)
        (c.permissions.map (·.authorityId) ++ c.prohibitions.map (·.authorityId)) =
        subset c.revoked (c.permissions.map (·.authorityId) ++ c.prohibitions.map (·.authorityId)) := by
      simp only [subset, List.all_cons, contains, Bool.true_and]
    have relEq (ps : List Path) : corpusRelationsValid (revoke c target) ps = corpusRelationsValid c ps := by
      unfold corpusRelationsValid
      simp only [revoke]
      rw [subsetEq]
      rfl
    unfold validateCorpus
    have eqbuild : buildPath (revoke c target) = buildPath c := funext (buildPath_revoked c target)
    simp only [eqbuild, relEq]
    rfl

theorem selectLoop_revoked (c : Corpus) (paths : List Path) (actor target : Id)
    (fuel : Nat) (seen : List Id) (queue : List Requirement) (graph : Graph) :
    selectLoop (revoke c target) paths actor fuel seen queue graph =
      selectLoop c paths actor fuel seen queue graph := by
  induction fuel generalizing seen queue graph with
  | zero => cases queue <;> rfl
  | succ fuel ih =>
    cases queue with
    | nil => rfl
    | cons req queue =>
      simp only [selectLoop]
      split
      · exact ih _ _ _
      · split
        · exact ih _ _ _
        · have recognizeEq (p : Path) : recognize (revoke c target) p = recognize c p := rfl
          simp only [recognizeEq]
          split <;> exact ih _ _ _

theorem selectGraph_revoked (c : Corpus) (paths : List Path) (main : Path) (actor target : Id) :
    selectGraph (revoke c target) paths main actor = selectGraph c paths main actor := by
  simp only [selectGraph, selectLoop_revoked]
  rfl

theorem guard_excludes_revocation (c : Corpus) (paths : List Path) (id : Id)
    (guard : revocationGuard c paths id = true) (p : Prohibition)
    (member : p ∈ c.prohibitions) (unrevoked : c.revoked.contains p.authorityId = false) :
    prohibitionAnchors paths p id = false := by
  simp only [revocationGuard, Bool.and_eq_true] at guard
  have absent : c.prohibitions.any
      (fun p => !c.revoked.contains p.authorityId && prohibitionAnchors paths p id) = false := by
    simpa using guard.2
  have no := List.any_eq_false.mp absent p member
  apply Bool.eq_false_iff.mpr
  simpa only [unrevoked, Bool.not_false, Bool.true_and] using no

theorem guard_target_diff_prohibition (c : Corpus) (paths : List Path) (target : Id)
    (wf : corpusStatus c = .valid) (guard : revocationGuard c paths target = true)
    (p : Prohibition) (member : p ∈ c.prohibitions) : p.authorityId ≠ target := by
  have existsPermission : (permission c target).isSome = true := by
    have parts := guard
    simp only [revocationGuard, Bool.and_eq_true] at parts
    exact parts.1.1
  cases found : permission c target with
  | none => simp [found] at existsPermission
  | some g =>
    have gm : g ∈ c.permissions := List.mem_of_find?_eq_some found
    have key : g.authorityId = target := by simpa using List.find?_some found
    intro equal
    exact permission_prohibition_ids_disjoint c wf g gm p member (key.trans equal.symm)

theorem revoked_contains_unchanged (c : Corpus) (target id : Id) (different : id ≠ target) :
    (revoke c target).revoked.contains id = c.revoked.contains id := by
  simp [revoke, different]

theorem path_revocation_unchanged (c : Corpus) (path : Path) (target : Id)
    (avoids : path.ids.contains target = false) (t : Nat) :
    pathActive (revoke c target) path t = pathActive c path t := by
  unfold pathActive
  apply all_congr_mem
  intro g member
  have different : g.authorityId ≠ target := by
    intro eq
    have present : path.ids.contains target = true := by
      simp only [Path.ids, List.contains_iff_mem, List.mem_map]
      exact ⟨g, member, eq⟩
    rw [avoids] at present
    contradiction
  rw [revoked_contains_unchanged c target g.authorityId different]
  rfl

theorem guard_preserves_prohibition_activity_revoked (c : Corpus) (paths : List Path) (target : Id)
    (wf : corpusStatus c = .valid) (guard : revocationGuard c paths target = true)
    (p : Prohibition) (member : p ∈ c.prohibitions) (t : Nat) :
    prohibitionActive (revoke c target) paths p t = prohibitionActive c paths p t := by
  have different := guard_target_diff_prohibition c paths target wf guard p member
  have rev := revoked_contains_unchanged c target p.authorityId different
  by_cases revoked : c.revoked.contains p.authorityId = true
  · simp only [prohibitionActive, rev, revoked, Bool.not_true, Bool.false_and]
  · have unrevoked : c.revoked.contains p.authorityId = false := Bool.eq_false_iff.mpr revoked
    have noAnchor := guard_excludes_revocation c paths target guard p member unrevoked
    unfold prohibitionActive
    rw [rev]
    congr 1
    split
    · rfl
    · cases parent : p.parentAuthorityId with
      | none => rfl
      | some id =>
        cases found : paths.find? (fun q => q.terminal.authorityId == id) with
        | none => simp only [found, Option.any_none]
        | some path =>
          have avoids : path.ids.contains target = false := by
            simpa [prohibitionAnchors, anchorPath, parent, found] using noAnchor
          simpa only [found, Option.any_some] using path_revocation_unchanged c path target avoids t

theorem matching_prohibitions_revoked (c : Corpus) (paths : List Path) (target : Id)
    (wf : corpusStatus c = .valid) (guard : revocationGuard c paths target = true)
    (graph : Graph) (r : Request) (t : Nat) :
    (c.prohibitions.filter (fun p => prohibitionApplies p graph r)).filter
        (fun p => prohibitionActive (revoke c target) paths p t && prohibitionAmount p r) =
    (c.prohibitions.filter (fun p => prohibitionApplies p graph r)).filter
        (fun p => prohibitionActive c paths p t && prohibitionAmount p r) := by
  apply filter_congr_mem
  intro p member
  rw [guard_preserves_prohibition_activity_revoked c paths target wf guard p
    (List.mem_filter.mp member).1 t]

theorem global_matches_revoked (c : Corpus) (paths : List Path) (target : Id)
    (wf : corpusStatus c = .valid) (guard : revocationGuard c paths target = true)
    (r : Request) (t : Nat) :
    globalMatches (revoke c target) paths r t = globalMatches c paths r t := by
  unfold globalMatches
  change c.prohibitions.filter _ = c.prohibitions.filter _
  apply filter_congr_mem
  intro p member
  rw [guard_preserves_prohibition_activity_revoked c paths target wf guard p member t]

#print axioms buildUp_revoked
#print axioms buildPath_revoked
#print axioms validation_revoked
#print axioms selectLoop_revoked
#print axioms selectGraph_revoked
#print axioms guard_excludes_revocation
#print axioms guard_target_diff_prohibition
#print axioms revoked_contains_unchanged
#print axioms path_revocation_unchanged
#print axioms guard_preserves_prohibition_activity_revoked
#print axioms matching_prohibitions_revoked
#print axioms global_matches_revoked
end Authority.G64

namespace Authority.G65
open Authority.G64

theorem failure_sets_revoked_backward (format2Usage : List Usage) (c : Corpus) (target : Id)
    (graph : Graph) (r : Request) (t : Nat)
    (success : firstFailure (failureSets format2Usage (revoke c target) graph r t) = none) :
    firstFailure (failureSets format2Usage c graph r t) = none := by
  have each := (firstFailure_empty _).mp success
  have noAfter := each (.REVOKED,
    (graph.grants.filter (fun p => (revoke c target).revoked.contains p.authorityId)).map (·.authorityId))
    (by simp [failureSets])
  dsimp only at noAfter
  have afterLive : ∀ p ∈ graph.grants, (revoke c target).revoked.contains p.authorityId = false := by
    simpa using noAfter
  have beforeLive : ∀ p ∈ graph.grants, c.revoked.contains p.authorityId = false := by
    intro p member
    have h := afterLive p member
    simp only [revoke, List.contains_cons, Bool.or_eq_false_iff] at h
    exact h.2
  have noBefore : (graph.grants.filter (fun p => c.revoked.contains p.authorityId)).map (·.authorityId) = [] := by
    simpa using beforeLive
  have equal : failureSets format2Usage c graph r t = failureSets format2Usage (revoke c target) graph r t := by
    unfold failureSets
    simp only [noAfter, noBefore]
    rfl
  rw [equal]
  exact success

theorem candidate_revocation_nonexpansion (format2Usage : List Usage) (c : Corpus) (paths : List Path)
    (target : Id) (wf : corpusStatus c = .valid) (guard : revocationGuard c paths target = true)
    (globals : List Prohibition) (main : Path) (r : Request) (t : Nat) (a : Candidate)
    (success : evaluateCandidate format2Usage (revoke c target) paths globals main r t = .ok a) :
    evaluateCandidate format2Usage c paths globals main r t = .ok a := by
  have afterNone := candidate_constraints format2Usage (revoke c target) paths globals main r t a success
  rw [selectGraph_revoked] at afterNone
  have beforeNone := failure_sets_revoked_backward format2Usage c target _ r t afterNone
  unfold evaluateCandidate at success ⊢
  rw [selectGraph_revoked] at success
  have recog : recognize (revoke c target) main = recognize c main := rfl
  have prohs : (revoke c target).prohibitions = c.prohibitions := rfl
  simp only [recog, prohs, afterNone, matching_prohibitions_revoked c paths target wf guard] at success
  simpa only [beforeNone] using success

set_option linter.unusedVariables false in
/-- ASM-1 at the algebra: a guarded revocation never creates an algebra ALLOW.
    The exact requested validation premise is retained even though the proof
    establishes the implication for every fixed path list satisfying the guard. -/
theorem revocation_algebra_nonexpansion (format2Usage : List Usage) (c : Corpus) (paths : List Path)
    (id : Id) (wf : corpusStatus c = .valid) (hv : validateCorpus c = .ok paths)
    (guard : revocationGuard c paths id = true)
    (r : Request) (t : Nat) (admin : Path → Bool) (a : Candidate)
    (success : evaluateAlgebra format2Usage (revoke c id) paths r t admin = .allow a) :
    ∃ before, evaluateAlgebra format2Usage c paths r t admin = .allow before := by
  obtain ⟨main, member, independent, actor, adminOK, selected⟩ :=
    algebra_origin format2Usage _ paths r t admin a success
  have noGlobal := algebra_no_global_blocks format2Usage _ paths r t admin a success
  rw [global_matches_revoked c paths id wf guard] at noGlobal
  exact algebra_exists_allow format2Usage c paths r t admin main a noGlobal member independent actor adminOK
    (candidate_revocation_nonexpansion format2Usage c paths id wf guard _ main r t a selected)

/-- ASM-1 at the A-133.2 stage (`allow` of F.5): the theorem r5.2 cites. -/
theorem revised_allow_revocation_nonexpansion (ledger : List Usage) (c : Corpus) (paths : List Path)
    (id : Id) (wf : corpusStatus c = .valid) (hv : validateCorpus c = .ok paths)
    (guard : revocationGuard c paths id = true)
    (r : Request) (t : Nat) (collision : Bool) (admin : Path → Bool)
    (success : revisedAllow (finalDecision ledger (revoke c id) paths r t collision admin) = true) :
    revisedAllow (finalDecision ledger c paths r t collision admin) = true := by
  rw [revised_allow_exact] at success ⊢
  have parts : allows (evaluateAlgebra ledger (revoke c id) paths r t admin) = true ∧ (!collision) = true := by
    simpa only [Bool.and_eq_true] using success
  cases afterEq : evaluateAlgebra ledger (revoke c id) paths r t admin with
  | deny fs => simp [afterEq, allows] at parts
  | indeterminate code => simp [afterEq, allows] at parts
  | allow a =>
    obtain ⟨before, beforeEq⟩ := revocation_algebra_nonexpansion ledger c paths id wf hv guard r t admin a afterEq
    simp only [beforeEq, allows, Bool.true_and]
    exact parts.2

#print axioms failure_sets_revoked_backward
#print axioms candidate_revocation_nonexpansion
#print axioms revocation_algebra_nonexpansion
#print axioms revised_allow_revocation_nonexpansion
end Authority.G65
