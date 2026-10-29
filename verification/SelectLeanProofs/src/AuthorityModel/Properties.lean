import AuthorityModel.Authority
namespace Authority

variable {format2Usage : List Usage}

theorem sorted_eq_nil (xs : List Id) : sorted xs = [] ↔ xs = [] := by
  constructor
  · intro h
    have hlen := congrArg List.length h
    simp [sorted] at hlen
    exact hlen
  · intro h; simp [h, sorted]

theorem firstFailure_none (sets : List (Code × List Id)) :
    firstFailure sets = none ↔ ∀ entry ∈ sets, entry.2 = [] := by
  induction sets with
  | nil => simp [firstFailure]
  | cons entry rest ih =>
    rcases entry with ⟨code, ids⟩
    simp only [firstFailure]
    cases hs : (sorted ids).head? with
    | none =>
      have empty : ids = [] := (sorted_eq_nil ids).mp (List.head?_eq_none_iff.mp hs)
      simp [ih, empty]
    | some id =>
      have nonempty : ids ≠ [] := by intro h; simp [h, sorted] at hs
      simp [nonempty]

theorem firstFailure_first_nonempty (code : Code) (ids : List Id) (rest : List (Code × List Id))
    (id : Id) (h : (sorted ids).head? = some id) :
    firstFailure ((code,ids)::rest) = some (code,id) := by simp [firstFailure, h]

theorem firstFailure_skip_empty (code : Code) (rest : List (Code × List Id)) :
    firstFailure ((code,[])::rest) = firstFailure rest := by simp [firstFailure, sorted]

theorem candidate_success_constraints (c : Corpus) (paths : List Path) (globals : List Prohibition)
    (main : Path) (r : Request) (t : Nat) (a : Candidate)
    (h : evaluateCandidate (format2Usage := format2Usage) c paths globals main r t = .ok a) :
    firstFailure (failureSets (format2Usage := format2Usage) c (selectGraph c paths main r.actorId) r t) = none := by
  unfold evaluateCandidate at h
  split at h
  · contradiction
  · dsimp only at h
    split at h
    · contradiction
    · split at h
      · contradiction
      · assumption

theorem candidate_success_graph (c : Corpus) (paths : List Path) (globals : List Prohibition)
    (main : Path) (r : Request) (t : Nat) (a : Candidate)
    (h : evaluateCandidate (format2Usage := format2Usage) c paths globals main r t = .ok a) :
    a.graph = selectGraph c paths main r.actorId := by
  unfold evaluateCandidate at h
  split at h
  · contradiction
  · dsimp only at h
    split at h
    · contradiction
    · split at h
      · contradiction
      · cases h; rfl

theorem candidate_success_all_failure_sets_empty (c : Corpus) (paths : List Path) (globals : List Prohibition)
    (main : Path) (r : Request) (t : Nat) (a : Candidate)
    (h : evaluateCandidate (format2Usage := format2Usage) c paths globals main r t = .ok a) :
    ∀ entry ∈ failureSets (format2Usage := format2Usage) c a.graph r t, entry.2 = [] := by
  rw [candidate_success_graph c paths globals main r t a h]
  exact (firstFailure_none _).mp (candidate_success_constraints c paths globals main r t a h)

theorem candidate_success_no_missing (c : Corpus) (paths : List Path) (globals : List Prohibition)
    (main : Path) (r : Request) (t : Nat) (a : Candidate)
    (h : evaluateCandidate (format2Usage := format2Usage) c paths globals main r t = .ok a) : a.graph.missing = [] := by
  have hall := candidate_success_all_failure_sets_empty c paths globals main r t a h
  exact hall (.MISSING_INTERSECTION, a.graph.missing) (by simp [failureSets])

theorem candidate_success_no_revoked (c : Corpus) (paths : List Path) (globals : List Prohibition)
    (main : Path) (r : Request) (t : Nat) (a : Candidate)
    (h : evaluateCandidate (format2Usage := format2Usage) c paths globals main r t = .ok a) :
    ∀ g ∈ a.graph.grants, c.revoked.contains g.authorityId = false := by
  have empty := candidate_success_all_failure_sets_empty c paths globals main r t a h
    (.REVOKED, (a.graph.grants.filter (fun p => c.revoked.contains p.authorityId)).map (·.authorityId))
    (by simp [failureSets])
  simpa using empty

theorem candidate_success_actions (c : Corpus) (paths : List Path) (globals : List Prohibition)
    (main : Path) (r : Request) (t : Nat) (a : Candidate)
    (h : evaluateCandidate (format2Usage := format2Usage) c paths globals main r t = .ok a) :
    ∀ g ∈ a.graph.grants, g.constraints.actions.contains r.action = true := by
  have empty := candidate_success_all_failure_sets_empty c paths globals main r t a h
    (.ACTION_NOT_ALLOWED, (a.graph.grants.filter (fun p => !p.constraints.actions.contains r.action)).map (·.authorityId))
    (by simp [failureSets])
  simpa using empty

theorem candidate_success_resources (c : Corpus) (paths : List Path) (globals : List Prohibition)
    (main : Path) (r : Request) (t : Nat) (a : Candidate)
    (h : evaluateCandidate (format2Usage := format2Usage) c paths globals main r t = .ok a) :
    ∀ g ∈ a.graph.grants, g.constraints.resources.contains r.resource = true := by
  have empty := candidate_success_all_failure_sets_empty c paths globals main r t a h
    (.RESOURCE_NOT_ALLOWED, (a.graph.grants.filter (fun p => !p.constraints.resources.contains r.resource)).map (·.authorityId))
    (by simp [failureSets])
  simpa using empty

/-- Dominance scoped to algebra: earlier input/session errors may win. -/
theorem global_prohibition_dominance (c : Corpus) (paths : List Path) (r : Request) (t : Nat)
    (admin : Path → Bool) (id : Id)
    (h : (sorted ((globalMatches c paths r t).map (·.authorityId))).head? = some id) :
    evaluateAlgebra (format2Usage := format2Usage) c paths r t admin = .deny [{
      code := .PROHIBITED
      subjectId := some r.actorId, failingAuthorityId := some id }] := by
  simp [evaluateAlgebra, h]

theorem budget_cannot_enable (d : Decision) (b : Option Code) (a : Candidate)
    (h : withBudget b d = .allow a) : d = .allow a := by
  cases d <;> cases b <;> simp_all [withBudget, deny]

theorem finalize_cannot_enable (c : Corpus) (d : Decision) (a : Candidate)
    (h : finalize c d = .allow a) : d = .allow a := by
  cases d <;> simp_all [finalize]
  split at h <;> simp_all

theorem attenuation_actions (p c : Constraints) (h : attenuated p c = true) : subset c.actions p.actions = true := by
  simp only [attenuated, Bool.and_eq_true] at h
  exact h.1.1.1.1.1.1.1.1.1.1

theorem attenuation_resources (p c : Constraints) (h : attenuated p c = true) : subset c.resources p.resources = true := by
  simp only [attenuated, Bool.and_eq_true] at h
  exact h.1.1.1.1.1.1.1.1.1.2

theorem subset_trans (a b c : List Id) (hab : subset a b = true) (hbc : subset b c = true) : subset a c = true := by
  simp only [subset, List.all_eq_true, List.contains_iff_mem] at *
  exact fun x hx => hbc x (hab x hx)

inductive AttenuationChain : Constraints → Constraints → Prop where
  | refl (c) : AttenuationChain c c
  | step {root parent child} : AttenuationChain root parent → attenuated parent child = true → AttenuationChain root child

theorem chain_actions_nonamplification {root child : Constraints} (h : AttenuationChain root child) :
    subset child.actions root.actions = true := by
  induction h with
  | refl => simp [subset]
  | step h hc ih => exact subset_trans _ _ _ (attenuation_actions _ _ hc) ih

theorem chain_resources_nonamplification {root child : Constraints} (h : AttenuationChain root child) :
    subset child.resources root.resources = true := by
  induction h with
  | refl => simp [subset]
  | step h hc ih => exact subset_trans _ _ _ (attenuation_resources _ _ hc) ih

theorem intersection_actions_nonamplification (a b : Constraints) :
    subset (combinePair a b).actions a.actions = true := by
  simp only [subset, combinePair, List.all_eq_true, List.contains_iff_mem]
  intro x hx; exact (List.mem_filter.mp hx).1

theorem intersection_resources_nonamplification (a b : Constraints) :
    subset (combinePair a b).resources a.resources = true := by
  simp only [subset, combinePair, List.all_eq_true, List.contains_iff_mem]
  intro x hx; exact (List.mem_filter.mp hx).1

theorem succession_preserves_permissions (s : State) (id : Id) :
    (closeTenure s id).corpus.permissions = s.corpus.permissions := rfl

theorem termination_preserves_permission_records (s : State) (id : Id) :
    (terminateAgent s id).corpus.permissions = s.corpus.permissions := rfl

theorem algebra_allow_origin (c : Corpus) (paths : List Path) (r : Request) (t : Nat)
    (admin : Path → Bool) (a : Candidate)
    (h : evaluateAlgebra (format2Usage := format2Usage) c paths r t admin = .allow a) :
    ∃ main ∈ paths, main.independent = true ∧ main.terminal.granteeId = r.actorId ∧
      evaluateCandidate (format2Usage := format2Usage) c paths (c.prohibitions.filter (fun p => p.scope == .GLOBAL && prohibitionRelevant p r)) main r t = .ok a := by
  unfold evaluateAlgebra at h
  dsimp only at h
  split at h
  · contradiction
  · split at h
    · rename_i winner heq
      cases h
      have hm := List.mem_of_head? heq
      simp only [List.mem_mergeSort, List.mem_filterMap, List.mem_map] at hm
      rcases hm with ⟨result, ⟨main, hp, hr⟩, hs⟩
      cases result with
      | error fail => simp at hs
      | ok success =>
        simp only [Option.some.injEq] at hs
        cases hs
        simp only [List.mem_filter, Bool.and_eq_true, beq_iff_eq] at hp
        exact ⟨main, hp.1, hp.2.1.1, hp.2.1.2, hr⟩
    · split at h <;> contradiction

theorem algebra_allow_every_constraint (c : Corpus) (paths : List Path) (r : Request) (t : Nat)
    (admin : Path → Bool) (a : Candidate)
    (h : evaluateAlgebra (format2Usage := format2Usage) c paths r t admin = .allow a) :
    ∀ entry ∈ failureSets (format2Usage := format2Usage) c a.graph r t, entry.2 = [] := by
  obtain ⟨main, _, _, _, hs⟩ := algebra_allow_origin c paths r t admin a h
  exact candidate_success_all_failure_sets_empty c paths _ main r t a hs

theorem upperBound_trans (a b c : Option Nat)
    (hab : upperBound a b = true) (hbc : upperBound b c = true) : upperBound a c = true := by
  cases a <;> cases b <;> cases c <;> simp_all [upperBound] <;> omega

theorem lowerBound_trans (a b c : Option Nat)
    (hab : lowerBound a b = true) (hbc : lowerBound b c = true) : lowerBound a c = true := by
  cases a <;> cases b <;> cases c <;> simp_all [lowerBound] <;> omega

theorem attenuation_amount (p c : Constraints) (h : attenuated p c = true) :
    upperBound p.maxAmount c.maxAmount = true := by
  simp only [attenuated, Bool.and_eq_true] at h
  exact h.1.1.2

theorem attenuation_cumulative (p c : Constraints) (h : attenuated p c = true) :
    upperBound p.maxCumulativeAmount c.maxCumulativeAmount = true := by
  simp only [attenuated, Bool.and_eq_true] at h
  exact h.1.2

theorem attenuation_count (p c : Constraints) (h : attenuated p c = true) :
    upperBound p.maxTransactions c.maxTransactions = true := by
  simp only [attenuated, Bool.and_eq_true] at h
  exact h.2

theorem chain_amount_nonamplification {root child : Constraints} (h : AttenuationChain root child) :
    upperBound root.maxAmount child.maxAmount = true := by
  induction h with
  | refl => cases root.maxAmount <;> simp [upperBound]
  | step h hc ih => exact upperBound_trans _ _ _ ih (attenuation_amount _ _ hc)

theorem chain_cumulative_nonamplification {root child : Constraints} (h : AttenuationChain root child) :
    upperBound root.maxCumulativeAmount child.maxCumulativeAmount = true := by
  induction h with
  | refl => cases root.maxCumulativeAmount <;> simp [upperBound]
  | step h hc ih => exact upperBound_trans _ _ _ ih (attenuation_cumulative _ _ hc)

theorem chain_count_nonamplification {root child : Constraints} (h : AttenuationChain root child) :
    upperBound root.maxTransactions child.maxTransactions = true := by
  induction h with
  | refl => cases root.maxTransactions <;> simp [upperBound]
  | step h hc ih => exact upperBound_trans _ _ _ ih (attenuation_count _ _ hc)

theorem optMin_narrows_left (a b : Option Nat) : upperBound a (optMin a b) = true := by
  cases a <;> cases b <;> simp [upperBound, optMin] <;> omega

theorem intersection_amount_nonamplification (a b : Constraints) :
    upperBound a.maxAmount (combinePair a b).maxAmount = true := optMin_narrows_left _ _

theorem intersection_cumulative_nonamplification (a b : Constraints) :
    upperBound a.maxCumulativeAmount (combinePair a b).maxCumulativeAmount = true := optMin_narrows_left _ _

theorem intersection_count_nonamplification (a b : Constraints) :
    upperBound a.maxTransactions (combinePair a b).maxTransactions = true := optMin_narrows_left _ _

theorem buildPath_links_valid (c : Corpus) (g : Permission) (p : Path)
    (h : buildPath c g = .ok p) : pathLinksValid p.grants = true := by
  unfold buildPath at h
  cases hs : buildUp c 32 [] g with
  | error e => simp [hs, bind, Except.bind] at h
  | ok gs =>
    simp only [hs, Except.bind, bind, pure] at h
    split at h
    · cases h; assumption
    · contradiction

theorem mapM_buildPath_valid (c : Corpus) (gs : List Permission) (paths : List Path)
    (h : gs.mapM (buildPath c) = .ok paths) : ∀ p ∈ paths, pathLinksValid p.grants = true := by
  induction gs generalizing paths with
  | nil => simp at h; cases h; simp
  | cons g gs ih =>
    simp only [List.mapM_cons] at h
    cases hg : buildPath c g with
    | error e => simp [hg, bind, Except.bind] at h
    | ok path =>
      cases hs : gs.mapM (buildPath c) with
      | error e => simp [hg, hs, bind, Except.bind] at h
      | ok rest =>
        simp [hg, hs, bind, Except.bind] at h
        cases h
        intro p hp
        rcases List.mem_cons.mp hp with hsame | hrest
        · cases hsame; exact buildPath_links_valid c g path hg
        · exact ih rest hs p hrest

theorem validateCorpus_path_links (c : Corpus) (paths : List Path)
    (h : validateCorpus c = .ok paths) : ∀ p ∈ paths, pathLinksValid p.grants = true := by
  unfold validateCorpus at h
  cases hs : c.permissions.mapM (buildPath c) with
  | error e => simp [hs, bind, Except.bind] at h
  | ok ps =>
    simp only [hs, Except.bind, bind] at h
    split at h
    · contradiction
    · split at h
      · cases h; exact mapM_buildPath_valid c c.permissions paths hs
      · contradiction

theorem selectLoop_preserves_main (c : Corpus) (paths : List Path) (actor : Id)
    (fuel : Nat) (seen : List Id) (queue : List Requirement) (graph : Graph) :
    (selectLoop c paths actor fuel seen queue graph).main = graph.main := by
  induction fuel generalizing seen queue graph with
  | zero => cases queue <;> rfl
  | succ n ih =>
    cases queue with
    | nil => rfl
    | cons req rest =>
      simp only [selectLoop]
      split
      · exact ih _ _ _
      · split
        · exact ih _ _ _
        · split <;> exact ih _ _ _

theorem selectGraph_preserves_main (c : Corpus) (paths : List Path) (main : Path) (actor : Id) :
    (selectGraph c paths main actor).main = main := by
  simp only [selectGraph]
  exact selectLoop_preserves_main _ _ _ _ _ _ _

theorem validated_algebra_allow_has_valid_main (c : Corpus) (paths : List Path) (r : Request) (t : Nat)
    (admin : Path → Bool) (a : Candidate) (hv : validateCorpus c = .ok paths)
    (ha : evaluateAlgebra (format2Usage := format2Usage) c paths r t admin = .allow a) :
    pathLinksValid a.graph.main.grants = true ∧
    ∀ entry ∈ failureSets (format2Usage := format2Usage) c a.graph r t, entry.2 = [] := by
  obtain ⟨main, hmem, _, _, hs⟩ := algebra_allow_origin c paths r t admin a ha
  constructor
  · rw [candidate_success_graph c paths _ main r t a hs]
    rw [selectGraph_preserves_main]
    exact validateCorpus_path_links c paths hv main hmem
  · exact algebra_allow_every_constraint c paths r t admin a ha

theorem stage_allow_algebra (s : State) (i : Input) (paths : List Path) (a : Candidate)
    (h : stageAfterCorpus s i paths = .allow a) :
    evaluateAlgebra (format2Usage := s.format2Usage) s.corpus paths i.request i.evaluationTime = .allow a := by
  unfold stageAfterCorpus at h
  split at h
  · simp [deny] at h
  · split at h
    · simp [deny] at h
    · dsimp only at h
      split at h
      · simp [deny] at h
      · split at h
        · rename_i candidate heq
          split at h
          · simp [deny] at h
          · have hf := finalize_cannot_enable s.corpus (.allow candidate) a h
            simpa [hf] using heq
        · assumption

theorem authorizeState_allow_validated (s : State) (i : Input) (a : Candidate)
    (h : authorizeState s i = .allow a) :
    ∃ paths, validateCorpus s.corpus = .ok paths ∧
      evaluateAlgebra (format2Usage := s.format2Usage) s.corpus paths i.request i.evaluationTime = .allow a := by
  unfold authorizeState at h
  split at h
  · contradiction
  · split at h
    · contradiction
    · split at h
      · simp [deny] at h
      · split at h
        · simp [deny] at h
        · split at h
          · simp [deny] at h
          · split at h
            · contradiction
            · simp [deny] at h
            · rename_i paths hv
              exact ⟨paths, hv, stage_allow_algebra s i paths a h⟩

theorem authorizeState_soundness (s : State) (i : Input) (a : Candidate)
    (h : authorizeState s i = .allow a) :
    pathLinksValid a.graph.main.grants = true ∧
    ∀ entry ∈ failureSets (format2Usage := s.format2Usage) s.corpus a.graph i.request i.evaluationTime, entry.2 = [] := by
  obtain ⟨paths, hv, ha⟩ := authorizeState_allow_validated s i a h
  exact validated_algebra_allow_has_valid_main s.corpus paths i.request i.evaluationTime _ a hv ha

theorem candidate_success_recognized (c : Corpus) (paths : List Path) (globals : List Prohibition)
    (main : Path) (r : Request) (t : Nat) (a : Candidate)
    (h : evaluateCandidate (format2Usage := format2Usage) c paths globals main r t = .ok a) :
    ∃ root, recognize c a.graph.main = some root := by
  rw [candidate_success_graph c paths globals main r t a h, selectGraph_preserves_main]
  cases hr : recognize c main with
  | none => simp [evaluateCandidate, hr] at h
  | some root => exact ⟨root, rfl⟩

theorem algebra_allow_no_global_blocks (c : Corpus) (paths : List Path) (r : Request) (t : Nat)
    (admin : Path → Bool) (a : Candidate) (h : evaluateAlgebra (format2Usage := format2Usage) c paths r t admin = .allow a) :
    globalMatches c paths r t = [] := by
  unfold evaluateAlgebra at h
  dsimp only at h
  split at h
  · contradiction
  · rename_i heq
    have hempty := (sorted_eq_nil _).mp (List.head?_eq_none_iff.mp heq)
    exact List.map_eq_nil_iff.mp hempty

theorem candidate_success_no_root_blocks (c : Corpus) (paths : List Path) (globals : List Prohibition)
    (main : Path) (r : Request) (t : Nat) (a : Candidate)
    (h : evaluateCandidate (format2Usage := format2Usage) c paths globals main r t = .ok a) :
    ((c.prohibitions.filter (fun p => prohibitionApplies p a.graph r)).filter
      (fun p => prohibitionActive c paths p t && prohibitionAmount p r)) = [] := by
  rw [candidate_success_graph c paths globals main r t a h]
  unfold evaluateCandidate at h
  split at h
  · contradiction
  · dsimp only at h
    split at h
    · contradiction
    · rename_i heq
      exact List.map_eq_nil_iff.mp ((sorted_eq_nil _).mp (List.head?_eq_none_iff.mp heq))

theorem selectLoop_partners_valid (c : Corpus) (paths : List Path) (actor : Id)
    (fuel : Nat) (seen : List Id) (queue : List Requirement) (graph : Graph)
    (initial : ∀ p ∈ graph.partners, p ∈ paths) :
    ∀ p ∈ (selectLoop c paths actor fuel seen queue graph).partners, p ∈ paths := by
  induction fuel generalizing seen queue graph with
  | zero => cases queue <;> exact initial
  | succ n ih =>
    cases queue with
    | nil => exact initial
    | cons req rest =>
      simp only [selectLoop]
      split
      · exact ih _ _ _ initial
      · split
        · exact ih _ _ _ initial
        · rename_i partner hp
          split
          · exact ih _ _ _ initial
          · apply ih
            intro p hmem
            simp only [List.mem_append, List.mem_singleton] at hmem
            rcases hmem with hmem | hsame
            · exact initial p hmem
            · cases hsame; exact List.mem_of_find?_eq_some hp

theorem selectGraph_partners_valid (c : Corpus) (paths : List Path) (main : Path) (actor : Id) :
    ∀ p ∈ (selectGraph c paths main actor).partners, p ∈ paths := by
  intro p hp
  simp only [selectGraph, List.mem_mergeSort] at hp
  exact selectLoop_partners_valid c paths actor _ _ _ _ (by simp) p hp

theorem authorizeState_all_paths_valid (s : State) (i : Input) (a : Candidate)
    (h : authorizeState s i = .allow a) :
    (∃ root, recognize s.corpus a.graph.main = some root) ∧
    (∀ p ∈ a.graph.paths, pathLinksValid p.grants = true) ∧
    (∀ entry ∈ failureSets (format2Usage := s.format2Usage) s.corpus a.graph i.request i.evaluationTime, entry.2 = []) ∧
    (∃ paths, validateCorpus s.corpus = .ok paths ∧ globalMatches s.corpus paths i.request i.evaluationTime = [] ∧
      ((s.corpus.prohibitions.filter (fun p => prohibitionApplies p a.graph i.request)).filter
        (fun p => prohibitionActive s.corpus paths p i.evaluationTime && prohibitionAmount p i.request)) = []) := by
  obtain ⟨paths, hv, ha⟩ := authorizeState_allow_validated s i a h
  obtain ⟨main, hmain, _, _, hc⟩ := algebra_allow_origin s.corpus paths i.request i.evaluationTime _ a ha
  refine ⟨candidate_success_recognized _ _ _ _ _ _ _ hc, ?_, algebra_allow_every_constraint _ _ _ _ _ _ ha, ?_⟩
  · intro p hp
    apply validateCorpus_path_links s.corpus paths hv p
    rw [candidate_success_graph _ _ _ _ _ _ _ hc] at hp
    simp only [Graph.paths, List.mem_cons] at hp
    rcases hp with hsame | hpartner
    · rw [selectGraph_preserves_main] at hsame
      simpa [hsame] using hmain
    · exact selectGraph_partners_valid _ _ _ _ p hpartner
  · exact ⟨paths, hv, algebra_allow_no_global_blocks _ _ _ _ _ _ ha,
      candidate_success_no_root_blocks _ _ _ _ _ _ _ hc⟩

theorem attenuation_notBefore (p c : Constraints) (h : attenuated p c = true) :
    lowerBound p.notBefore c.notBefore = true := by
  simp only [attenuated, Bool.and_eq_true] at h
  exact h.1.1.1.1.2

theorem attenuation_expiresAt (p c : Constraints) (h : attenuated p c = true) :
    upperBound p.expiresAt c.expiresAt = true := by
  simp only [attenuated, Bool.and_eq_true] at h
  exact h.1.1.1.2

theorem attenuation_inherits_intersections (p c : Constraints) (h : attenuated p c = true) :
    subset p.requiredIntersectionIds c.requiredIntersectionIds = true := by
  simp only [attenuated, Bool.and_eq_true] at h
  exact h.1.1.1.1.1.1.1.1.2

theorem attenuation_quantitative (p c : Constraints) (h : attenuated p c = true) :
    p.quantitative = true → c.quantitative = true := by
  simp only [attenuated, Bool.and_eq_true] at h
  have hq := h.1.1.1.1.1.2
  intro hp
  simpa [hp] using hq

theorem attenuation_depth (p c : Constraints) (h : attenuated p c = true) :
    c.maxDelegationDepth < p.maxDelegationDepth := by
  simp only [attenuated, Bool.and_eq_true, decide_eq_true_eq] at h
  exact h.1.1.1.1.1.1.2

theorem chain_notBefore_nonamplification {root child : Constraints} (h : AttenuationChain root child) :
    lowerBound root.notBefore child.notBefore = true := by
  induction h with
  | refl => cases root.notBefore <;> simp [lowerBound]
  | step h hc ih => exact lowerBound_trans _ _ _ ih (attenuation_notBefore _ _ hc)

theorem chain_expiry_nonamplification {root child : Constraints} (h : AttenuationChain root child) :
    upperBound root.expiresAt child.expiresAt = true := by
  induction h with
  | refl => cases root.expiresAt <;> simp [upperBound]
  | step h hc ih => exact upperBound_trans _ _ _ ih (attenuation_expiresAt _ _ hc)

theorem chain_inherits_intersections {root child : Constraints} (h : AttenuationChain root child) :
    subset root.requiredIntersectionIds child.requiredIntersectionIds = true := by
  induction h with
  | refl => simp [subset]
  | step h hc ih => exact subset_trans _ _ _ ih (attenuation_inherits_intersections _ _ hc)

theorem chain_quantitative_preserved {root child : Constraints} (h : AttenuationChain root child) :
    root.quantitative = true → child.quantitative = true := by
  induction h with
  | refl => exact id
  | step h hc ih => exact fun hr => attenuation_quantitative _ _ hc (ih hr)

theorem chain_depth_nonamplification {root child : Constraints} (h : AttenuationChain root child) :
    child.maxDelegationDepth ≤ root.maxDelegationDepth := by
  induction h with
  | refl => omega
  | step h hc ih => have hd := attenuation_depth _ _ hc; omega

theorem attenuationChain_trans {a b c : Constraints} (hab : AttenuationChain a b)
    (hbc : AttenuationChain b c) : AttenuationChain a c := by
  induction hbc with
  | refl => exact hab
  | step h hc ih => exact .step ih hc

theorem validated_path_is_chain (root : Permission) (rest : List Permission)
    (h : pathLinksValid (root :: rest) = true) :
    ∀ g ∈ root :: rest, AttenuationChain root.constraints g.constraints := by
  induction rest generalizing root with
  | nil => intro g hg; simp at hg; cases hg; exact .refl _
  | cons child rest ih =>
    simp only [pathLinksValid, Bool.and_eq_true] at h
    intro g hg
    rcases List.mem_cons.mp hg with hroot | htail
    · cases hroot; exact .refl _
    · have hchild := ih child h.2 g htail
      have hstep : AttenuationChain root.constraints child.constraints := .step (.refl _) h.1.2
      exact attenuationChain_trans hstep hchild

theorem binding_none_lifecycle_gates (s : State) (r : Request) (t : Nat) (actor : Agent) (b : Binding)
    (h : bindingProblem s r t actor b = none) :
    ∃ session, s.sessions.find? (·.id == b.runtimeSessionId) = some session ∧
      session.agentId = actor.id ∧ session.controlEpoch = actor.currentControlEpoch ∧
      b.controlEpoch = actor.currentControlEpoch ∧ tenureCurrent s actor.id b = true := by
  unfold bindingProblem at h
  split at h
  · contradiction
  · rename_i session hs
    refine ⟨session, hs, ?_⟩
    repeat first | split at h | contradiction
    all_goals simp_all <;> omega

theorem stage_allow_active_actor (s : State) (i : Input) (paths : List Path) (a : Candidate)
    (h : stageAfterCorpus s i paths = .allow a) :
    ∃ actor, (s.corpus.agents.getD []).find? (·.id == i.request.actorId) = some actor ∧ actor.terminated = false := by
  unfold stageAfterCorpus at h
  split at h
  · simp [deny] at h
  · rename_i actor hs
    split at h
    · simp [deny] at h
    · exact ⟨actor, hs, by simpa using ‹¬actor.terminated = true›⟩

#print axioms sorted_eq_nil
#print axioms firstFailure_none
#print axioms firstFailure_first_nonempty
#print axioms firstFailure_skip_empty
#print axioms candidate_success_constraints
#print axioms candidate_success_graph
#print axioms candidate_success_all_failure_sets_empty
#print axioms candidate_success_no_missing
#print axioms candidate_success_no_revoked
#print axioms candidate_success_actions
#print axioms candidate_success_resources
#print axioms global_prohibition_dominance
#print axioms budget_cannot_enable
#print axioms finalize_cannot_enable
#print axioms attenuation_actions
#print axioms attenuation_resources
#print axioms subset_trans
#print axioms chain_actions_nonamplification
#print axioms chain_resources_nonamplification
#print axioms intersection_actions_nonamplification
#print axioms intersection_resources_nonamplification
#print axioms succession_preserves_permissions
#print axioms termination_preserves_permission_records
#print axioms algebra_allow_origin
#print axioms algebra_allow_every_constraint
#print axioms upperBound_trans
#print axioms lowerBound_trans
#print axioms attenuation_amount
#print axioms attenuation_cumulative
#print axioms attenuation_count
#print axioms chain_amount_nonamplification
#print axioms chain_cumulative_nonamplification
#print axioms chain_count_nonamplification
#print axioms optMin_narrows_left
#print axioms intersection_amount_nonamplification
#print axioms intersection_cumulative_nonamplification
#print axioms intersection_count_nonamplification
#print axioms buildPath_links_valid
#print axioms mapM_buildPath_valid
#print axioms validateCorpus_path_links
#print axioms selectLoop_preserves_main
#print axioms selectGraph_preserves_main
#print axioms validated_algebra_allow_has_valid_main
#print axioms stage_allow_algebra
#print axioms authorizeState_allow_validated
#print axioms authorizeState_soundness
#print axioms candidate_success_recognized
#print axioms algebra_allow_no_global_blocks
#print axioms candidate_success_no_root_blocks
#print axioms selectLoop_partners_valid
#print axioms selectGraph_partners_valid
#print axioms authorizeState_all_paths_valid
#print axioms attenuation_notBefore
#print axioms attenuation_expiresAt
#print axioms attenuation_inherits_intersections
#print axioms attenuation_quantitative
#print axioms attenuation_depth
#print axioms chain_notBefore_nonamplification
#print axioms chain_expiry_nonamplification
#print axioms chain_inherits_intersections
#print axioms chain_quantitative_preserved
#print axioms chain_depth_nonamplification
#print axioms attenuationChain_trans
#print axioms validated_path_is_chain
#print axioms binding_none_lifecycle_gates
#print axioms stage_allow_active_actor
end Authority
