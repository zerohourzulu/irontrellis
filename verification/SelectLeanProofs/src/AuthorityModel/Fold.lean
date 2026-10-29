import AuthorityModel.Properties
namespace Authority

/-- All dimensions of non-amplification for an effective constraint record. -/
structure Refines (effective source : Constraints) : Prop where
  actions : subset effective.actions source.actions = true
  resources : subset effective.resources source.resources = true
  quantitative : source.quantitative = true → effective.quantitative = true
  notBefore : lowerBound source.notBefore effective.notBefore = true
  expiresAt : upperBound source.expiresAt effective.expiresAt = true
  amount : upperBound source.maxAmount effective.maxAmount = true
  cumulative : upperBound source.maxCumulativeAmount effective.maxCumulativeAmount = true
  count : upperBound source.maxTransactions effective.maxTransactions = true
  depth : effective.maxDelegationDepth ≤ source.maxDelegationDepth
  required : subset source.requiredIntersectionIds effective.requiredIntersectionIds = true

theorem refines_refl (c : Constraints) : Refines c c := by
  refine ⟨by simp [subset], by simp [subset], fun h => h, ?_, ?_, ?_, ?_, ?_, Nat.le_refl _, by simp [subset]⟩
  · cases h : c.notBefore <;> simp [lowerBound]
  · cases h : c.expiresAt <;> simp [upperBound]
  · cases h : c.maxAmount <;> simp [upperBound]
  · cases h : c.maxCumulativeAmount <;> simp [upperBound]
  · cases h : c.maxTransactions <;> simp [upperBound]

theorem optMax_narrows_left (a b : Option Nat) : lowerBound a (optMax a b) = true := by
  cases a <;> cases b <;> simp [lowerBound, optMax] <;> omega

theorem optMax_narrows_right (a b : Option Nat) : lowerBound b (optMax a b) = true := by
  cases a <;> cases b <;> simp [lowerBound, optMax] <;> omega

theorem optMin_narrows_right (a b : Option Nat) : upperBound b (optMin a b) = true := by
  cases a <;> cases b <;> simp [upperBound, optMin] <;> omega

theorem refines_trans {a b c : Constraints} (hab : Refines a b) (hbc : Refines b c) : Refines a c := by
  exact ⟨subset_trans _ _ _ hab.actions hbc.actions,
    subset_trans _ _ _ hab.resources hbc.resources,
    fun h => hab.quantitative (hbc.quantitative h),
    lowerBound_trans _ _ _ hbc.notBefore hab.notBefore,
    upperBound_trans _ _ _ hbc.expiresAt hab.expiresAt,
    upperBound_trans _ _ _ hbc.amount hab.amount,
    upperBound_trans _ _ _ hbc.cumulative hab.cumulative,
    upperBound_trans _ _ _ hbc.count hab.count,
    Nat.le_trans hab.depth hbc.depth,
    subset_trans _ _ _ hbc.required hab.required⟩

theorem mem_union_iff (id : Id) (xs : List Id) : id ∈ union xs ↔ id ∈ xs := by
  simp [union, sorted, List.mem_mergeSort]

theorem pair_refines_left (a b : Constraints) : Refines (combinePair a b) a := by
  constructor
  · exact intersection_actions_nonamplification a b
  · exact intersection_resources_nonamplification a b
  · intro h; simp [combinePair, h]
  · exact optMax_narrows_left _ _
  · exact optMin_narrows_left _ _
  · exact optMin_narrows_left _ _
  · exact optMin_narrows_left _ _
  · exact optMin_narrows_left _ _
  · exact Nat.min_le_left _ _
  · simp only [subset, combinePair, List.all_eq_true, List.contains_iff_mem]
    intro id hid; exact (mem_union_iff _ _).mpr (List.mem_append_left _ hid)

theorem pair_refines_right (a b : Constraints) : Refines (combinePair a b) b := by
  constructor
  · simp only [subset, combinePair, List.all_eq_true, List.contains_iff_mem]
    intro id hid; exact List.contains_iff_mem.mp (List.mem_filter.mp hid).2
  · simp only [subset, combinePair, List.all_eq_true, List.contains_iff_mem]
    intro id hid; exact List.contains_iff_mem.mp (List.mem_filter.mp hid).2
  · intro h; simp [combinePair, h]
  · exact optMax_narrows_right _ _
  · exact optMin_narrows_right _ _
  · exact optMin_narrows_right _ _
  · exact optMin_narrows_right _ _
  · exact optMin_narrows_right _ _
  · exact Nat.min_le_right _ _
  · simp only [subset, combinePair, List.all_eq_true, List.contains_iff_mem]
    intro id hid; exact (mem_union_iff _ _).mpr (List.mem_append_right _ hid)

theorem fold_refines_start (xs : List Permission) (start : Constraints) :
    Refines (xs.foldl (fun a p => combinePair a p.constraints) start) start := by
  induction xs generalizing start with
  | nil => exact refines_refl start
  | cons x xs ih => exact refines_trans (ih _) (pair_refines_left _ _)

theorem fold_refines_member (xs : List Permission) (start : Constraints) (g : Permission)
    (hg : g ∈ xs) : Refines (xs.foldl (fun a p => combinePair a p.constraints) start) g.constraints := by
  induction xs generalizing start with
  | nil => simp at hg
  | cons x xs ih =>
    simp only [List.mem_cons] at hg
    rcases hg with h | h
    · subst g; exact refines_trans (fold_refines_start xs _) (pair_refines_right _ _)
    · exact ih _ h

theorem sorted_constraints_refines (c : Constraints) :
    Refines ({ c with actions := sorted c.actions, resources := sorted c.resources, requiredIntersectionIds := sorted c.requiredIntersectionIds } : Constraints) c := by
  have h := refines_refl c
  constructor
  · simp [subset, sorted, List.all_eq_true, List.mem_mergeSort]
  · simp [subset, sorted, List.all_eq_true, List.mem_mergeSort]
  · exact h.quantitative
  · exact h.notBefore
  · exact h.expiresAt
  · exact h.amount
  · exact h.cumulative
  · exact h.count
  · exact h.depth
  · simp [subset, sorted, List.all_eq_true, List.mem_mergeSort]

/-- Every actual grant constrains the final executable fold. -/
theorem combined_refines_every_grant (gs : List Permission) (g : Permission) (hg : g ∈ gs) :
    Refines (combineConstraints gs) g.constraints := by
  cases gs with
  | nil => simp at hg
  | cons first rest =>
    simp only [List.mem_cons] at hg
    rcases hg with h | h
    · subst g
      exact refines_trans (fold_refines_start _ _) (sorted_constraints_refines first.constraints)
    · exact fold_refines_member _ _ _ h

theorem combined_graph_refines_path_grant (graph : Graph) (p : Path) (g : Permission)
    (hp : p ∈ graph.paths) (hg : g ∈ p.grants) :
    Refines (combineConstraints graph.grants) g.constraints := by
  apply combined_refines_every_grant
  exact List.mem_flatMap.mpr ⟨p, hp, hg⟩

#print axioms refines_refl
#print axioms optMax_narrows_left
#print axioms optMax_narrows_right
#print axioms optMin_narrows_right
#print axioms refines_trans
#print axioms mem_union_iff
#print axioms pair_refines_left
#print axioms pair_refines_right
#print axioms fold_refines_start
#print axioms fold_refines_member
#print axioms sorted_constraints_refines
#print axioms combined_refines_every_grant
#print axioms combined_graph_refines_path_grant
end Authority
