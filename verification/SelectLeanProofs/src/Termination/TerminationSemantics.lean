import Termination.TerminationGuard
namespace Authority.G64

theorem buildUp_terminated (c : Corpus) (target : Id) (fuel : Nat) (seen : List Id) (g : Permission) :
    buildUp (terminate c target) fuel seen g = buildUp c fuel seen g := by
  induction fuel generalizing seen g with
  | zero => rfl
  | succ fuel ih =>
    simp only [buildUp,permission,terminate]
    split
    · rfl
    · split
      · rfl
      · split
        · rfl
        · simpa only [terminate] using congrArg (fun x : Except Code (List Permission) => (do let ancestors ← x; pure (ancestors ++ [g]))) (ih (g.authorityId :: seen) _)

theorem buildPath_terminated (c : Corpus) (target : Id) (g : Permission) :
    buildPath (terminate c target) g = buildPath c g := by
  simp only [buildPath,buildUp_terminated]

theorem validation_terminated (c : Corpus) (target : Id) :
    validateCorpus (terminate c target) = validateCorpus c := by
  unfold validateCorpus
  have eqbuild : buildPath (terminate c target) = buildPath c := funext (buildPath_terminated c target)
  simp only [terminate]
  rfl

theorem pr_preserves_prohibition_activity (c : Corpus) (target : Id)
    (guard : prTermination c target = true) :
    ∃ paths, validateCorpus c = .ok paths ∧ validateCorpus (terminate c target) = .ok paths ∧
      ∀ p ∈ c.prohibitions, ∀ t,
        prohibitionActive (terminate c target) paths p t = prohibitionActive c paths p t := by
  unfold prTermination at guard
  cases valid : validateCorpus c with
  | error code => simp only [valid,Bool.false_eq_true] at guard
  | ok paths =>
    refine ⟨paths,rfl,?_,?_⟩
    · rw [validation_terminated,valid]
    · exact fun p member t => guard_preserves_prohibition_activity c paths target (by simpa only [valid] using guard) p member t

theorem selectLoop_terminated (c : Corpus) (paths : List Path) (actor target : Id)
    (fuel : Nat) (seen : List Id) (queue : List Requirement) (graph : Graph) :
    selectLoop (terminate c target) paths actor fuel seen queue graph = selectLoop c paths actor fuel seen queue graph := by
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
        · have recognizeEq (p : Path) : recognize (terminate c target) p = recognize c p := rfl
          simp only [recognizeEq]
          split <;> exact ih _ _ _

theorem selectGraph_terminated (c : Corpus) (paths : List Path) (main : Path) (actor target : Id) :
    selectGraph (terminate c target) paths main actor = selectGraph c paths main actor := by
  simp only [selectGraph,selectLoop_terminated]
  rfl

theorem inactive_live_backward (c : Corpus) (target id : Id)
    (live : inactive (terminate c target) id = false) : inactive c id = false := by
  unfold inactive terminate at *
  cases agents : c.agents with
  | none => rfl
  | some xs =>
    simp only [agents,Option.map_some,Option.getD_some,find_terminated] at live ⊢
    cases found : xs.find? (fun a => a.id == id) with
    | none => rfl
    | some a =>
      simp only [found,Option.map_some,Option.any_some] at live
      unfold terminateAgent at live
      split at live
      · contradiction
      · exact live

theorem path_active_backward (c : Corpus) (path : Path) (target : Id) (t : Nat)
    (live : pathActive (terminate c target) path t = true) : pathActive c path t = true := by
  simp only [pathActive,List.all_eq_true,Bool.and_eq_true,Bool.not_eq_true'] at live ⊢
  intro g member
  have h := live g member
  exact ⟨⟨⟨h.1.1.1,h.1.1.2⟩,inactive_live_backward c target g.grantorId h.1.2⟩,
    inactive_live_backward c target g.granteeId h.2⟩

#print axioms buildUp_terminated
#print axioms buildPath_terminated
#print axioms validation_terminated
#print axioms pr_preserves_prohibition_activity
#print axioms selectLoop_terminated
#print axioms selectGraph_terminated
#print axioms inactive_live_backward
#print axioms path_active_backward
end Authority.G64
