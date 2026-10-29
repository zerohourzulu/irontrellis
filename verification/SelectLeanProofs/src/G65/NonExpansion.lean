import G65.Candidate
namespace Authority.G65
open Authority.G64

/- A new G6.5 candidate-local termination theorem, with fixed independent
   format2Usage and unchanged ancillary predicate. Full authorize/replay
   equivalence is not asserted by this component. -/
theorem candidate_constraints (format2Usage : List Usage) (c : Corpus) (paths : List Path) (globals : List Prohibition)
    (main : Path) (r : Request) (t : Nat) (a : Candidate)
    (h : evaluateCandidate format2Usage c paths globals main r t = .ok a) :
    firstFailure (failureSets format2Usage c (selectGraph c paths main r.actorId) r t) = none := by
  unfold evaluateCandidate at h
  split at h
  · contradiction
  · dsimp only at h
    split at h
    · contradiction
    · split at h
      · contradiction
      · assumption

theorem failure_sets_backward (format2Usage : List Usage) (c : Corpus) (target : Id) (graph : Graph) (r : Request) (t : Nat)
    (success : firstFailure (failureSets format2Usage (terminate c target) graph r t) = none) :
    firstFailure (failureSets format2Usage c graph r t) = none := by
  have each := (firstFailure_empty _).mp success
  have noAfter := each (.NO_AUTHORITY,
    (graph.grants.filter (fun p => inactive (terminate c target) p.grantorId ||
      inactive (terminate c target) p.granteeId)).map (·.authorityId)) (by simp [failureSets])
  dsimp only at noAfter
  have afterLive : ∀ p ∈ graph.grants,
      inactive (terminate c target) p.grantorId = false ∧
      inactive (terminate c target) p.granteeId = false := by
    simpa using noAfter
  have beforeLive : ∀ p ∈ graph.grants,
      inactive c p.grantorId = false ∧ inactive c p.granteeId = false := by
    intro p member
    exact ⟨inactive_live_backward c target _ (afterLive p member).1,
      inactive_live_backward c target _ (afterLive p member).2⟩
  have noBefore : (graph.grants.filter (fun p => inactive c p.grantorId || inactive c p.granteeId)).map (·.authorityId) = [] := by
    simpa using beforeLive
  have equal : failureSets format2Usage c graph r t = failureSets format2Usage (terminate c target) graph r t := by
    unfold failureSets
    simp only [noAfter,noBefore]
    rfl
  rw [equal]; exact success

theorem candidate_nonexpansion (format2Usage : List Usage) (c : Corpus) (paths : List Path) (target : Id)
    (guard : terminationGuard c paths target = true) (globals : List Prohibition)
    (main : Path) (r : Request) (t : Nat) (a : Candidate)
    (success : evaluateCandidate format2Usage (terminate c target) paths globals main r t = .ok a) :
    evaluateCandidate format2Usage c paths globals main r t = .ok a := by
  have afterNone := candidate_constraints format2Usage (terminate c target) paths globals main r t a success
  rw [selectGraph_terminated] at afterNone
  have beforeNone := failure_sets_backward format2Usage c target _ r t afterNone
  unfold evaluateCandidate at success ⊢
  rw [selectGraph_terminated] at success
  have recog : recognize (terminate c target) main = recognize c main := rfl
  have prohs : (terminate c target).prohibitions = c.prohibitions := rfl
  simp only [recog,prohs,afterNone,matching_prohibitions_unchanged c paths target guard] at success
  simpa only [beforeNone] using success

theorem algebra_origin (format2Usage : List Usage) (c : Corpus) (paths : List Path) (r : Request) (t : Nat)
    (admin : Path → Bool) (a : Candidate)
    (h : evaluateAlgebra format2Usage c paths r t admin = .allow a) :
    ∃ main ∈ paths, main.independent = true ∧ main.terminal.granteeId = r.actorId ∧ admin main = true ∧
      evaluateCandidate format2Usage c paths (c.prohibitions.filter (fun p => p.scope == .GLOBAL && prohibitionRelevant p r)) main r t = .ok a := by
  unfold evaluateAlgebra at h
  dsimp only at h
  split at h
  · contradiction
  · split at h
    · rename_i winner heq
      cases h
      have hm := List.mem_of_head? heq
      simp only [List.mem_mergeSort,List.mem_filterMap,List.mem_map] at hm
      rcases hm with ⟨result,⟨main,hp,hr⟩,hs⟩
      cases result with
      | error fail => simp at hs
      | ok success =>
        simp only [Option.some.injEq] at hs
        cases hs
        simp only [List.mem_filter,Bool.and_eq_true,beq_iff_eq] at hp
        exact ⟨main,hp.1,hp.2.1.1,hp.2.1.2,hp.2.2,hr⟩
    · split at h <;> contradiction

theorem algebra_no_global_blocks (format2Usage : List Usage) (c : Corpus) (paths : List Path) (r : Request) (t : Nat)
    (admin : Path → Bool) (a : Candidate) (h : evaluateAlgebra format2Usage c paths r t admin = .allow a) :
    globalMatches c paths r t = [] := by
  unfold evaluateAlgebra at h
  dsimp only at h
  split at h
  · contradiction
  · rename_i heq
    have hempty := (sorted_empty _).mp (List.head?_eq_none_iff.mp heq)
    exact List.map_eq_nil_iff.mp hempty

theorem algebra_exists_allow (format2Usage : List Usage) (c : Corpus) (paths : List Path) (r : Request) (t : Nat)
    (admin : Path → Bool) (main : Path) (a : Candidate)
    (noGlobal : globalMatches c paths r t = [])
    (member : main ∈ paths) (independent : main.independent = true)
    (actor : main.terminal.granteeId = r.actorId) (adminOK : admin main = true)
    (success : evaluateCandidate format2Usage c paths (c.prohibitions.filter (fun p => p.scope == .GLOBAL && prohibitionRelevant p r)) main r t = .ok a) :
    ∃ winner, evaluateAlgebra format2Usage c paths r t admin = .allow winner := by
  unfold evaluateAlgebra
  simp only [noGlobal,List.map_nil,sorted,List.mergeSort_nil,List.head?_nil]
  let candidates := paths.filter (fun p => p.independent && p.terminal.granteeId == r.actorId && admin p)
  let results := candidates.map (fun p => evaluateCandidate format2Usage c paths (c.prohibitions.filter (fun p => p.scope == .GLOBAL && prohibitionRelevant p r)) p r t)
  let successes := results.filterMap (fun x => match x with | .ok y => some y | _ => none)
  have memCandidate : main ∈ candidates := by simp [candidates,member,independent,actor,adminOK]
  have memResult : Except.ok a ∈ results := List.mem_map.mpr ⟨main,memCandidate,success⟩
  have memSuccess : a ∈ successes := List.mem_filterMap.mpr ⟨.ok a,memResult,rfl⟩
  have memSorted : a ∈ successes.mergeSort (fun a b => compareCandidate a b != .gt) := List.mem_mergeSort.mpr memSuccess
  cases head : (successes.mergeSort (fun a b => compareCandidate a b != .gt)).head? with
  | none =>
    have empty := List.head?_eq_none_iff.mp head
    simp only [empty,List.not_mem_nil] at memSorted
  | some winner =>
    exact ⟨winner,rfl⟩

theorem algebra_nonexpansion (format2Usage : List Usage) (c : Corpus) (paths : List Path) (target : Id)
    (guard : terminationGuard c paths target = true) (r : Request) (t : Nat)
    (admin : Path → Bool) (a : Candidate)
    (success : evaluateAlgebra format2Usage (terminate c target) paths r t admin = .allow a) :
    ∃ before, evaluateAlgebra format2Usage c paths r t admin = .allow before := by
  obtain ⟨main,member,independent,actor,adminOK,selected⟩ := algebra_origin format2Usage _ paths r t admin a success
  have noGlobal := algebra_no_global_blocks format2Usage _ paths r t admin a success
  rw [global_matches_unchanged c paths target guard] at noGlobal
  exact algebra_exists_allow format2Usage c paths r t admin main a noGlobal member independent actor adminOK
    (candidate_nonexpansion format2Usage c paths target guard _ main r t a selected)

#print axioms candidate_constraints
#print axioms failure_sets_backward
#print axioms candidate_nonexpansion
#print axioms algebra_origin
#print axioms algebra_no_global_blocks
#print axioms algebra_exists_allow
#print axioms algebra_nonexpansion
end Authority.G65
