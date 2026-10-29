import AuthorityModel.Traversal
namespace Authority

def pendingCost (paths : List Path) (seen : List Id) : Nat :=
  match paths with
  | [] => 0
  | p::ps => (if seen.contains p.terminal.authorityId then 0 else (directRequirements p).length) + pendingCost ps seen

def traversalCost (paths : List Path) (s : TraversalState) : Nat :=
  s.queue.length + pendingCost paths s.seen

theorem pendingCost_add_le (paths : List Path) (seen : List Id) (id : Id) :
    pendingCost paths (id::seen) ≤ pendingCost paths seen := by
  induction paths with
  | nil => simp [pendingCost]
  | cons p ps ih =>
    simp only [pendingCost, List.contains_cons]
    cases hi : p.terminal.authorityId == id <;> cases hs : seen.contains p.terminal.authorityId <;> simp_all <;> omega

theorem pendingCost_pays (paths : List Path) (seen : List Id) (p : Path)
    (hp : p ∈ paths) (hs : seen.contains p.terminal.authorityId = false) :
    pendingCost paths (p.terminal.authorityId::seen) + (directRequirements p).length ≤ pendingCost paths seen := by
  induction paths with
  | nil => simp at hp
  | cons first rest ih =>
    simp only [List.mem_cons] at hp
    rcases hp with h | h
    · subst first
      have hl := pendingCost_add_le rest seen p.terminal.authorityId
      simp only [pendingCost, List.contains_cons, beq_self_eq_true, Bool.true_or, ↓reduceIte, hs, Bool.false_eq_true, Nat.zero_add]
      omega
    · have ht := ih h
      have hl := pendingCost_add_le [first] seen p.terminal.authorityId
      simp only [pendingCost, Nat.add_zero] at hl
      simp only [pendingCost]
      omega

theorem partnerFor_some (c : Corpus) (paths : List Path) (actor id : Id) (p : Path)
    (h : partnerFor c paths actor id = some p) :
    p ∈ paths ∧ p.terminal.authorityId = id := by
  unfold partnerFor at h
  cases hf : paths.find? (fun p => p.terminal.authorityId == id) with
  | none => simp [hf] at h
  | some q =>
    simp only [hf] at h
    split at h
    · contradiction
    · cases h
      have ht : (p.terminal.authorityId == id) = true := @List.find?_some Path (fun x => x.terminal.authorityId == id) p paths hf
      exact ⟨List.mem_of_find?_eq_some hf, by simpa using ht⟩

theorem traversalStep_decreases (c : Corpus) (paths : List Path) (actor : Id) (s : TraversalState)
    (hq : s.queue ≠ []) : traversalCost paths (traversalStep c paths actor s) < traversalCost paths s := by
  rcases s with ⟨seen,queue,graph⟩
  cases queue with
  | nil => contradiction
  | cons req queue =>
    simp only [traversalStep]
    cases hs : seen.contains req.requiredId
    · simp only [Bool.false_eq_true, ↓reduceIte]
      cases hp : partnerFor c paths actor req.requiredId with
      | none =>
        have hl := pendingCost_add_le paths seen req.requiredId
        simp only [traversalCost, List.length_cons]
        omega
      | some p =>
        obtain ⟨hm,he⟩ := partnerFor_some c paths actor req.requiredId p hp
        have hl := pendingCost_pays paths seen p hm (by simpa [he] using hs)
        simp only [traversalCost, List.length_append, List.length_cons]
        rw [he] at hl
        omega
    · simp only [↓reduceIte, traversalCost, List.length_cons]
      omega

/-- Sufficient fuel is proved against actual queue insertions, including
    duplicate requirements and arbitrary cycles. No tree assumption is used. -/
theorem traversal_drains (c : Corpus) (paths : List Path) (actor : Id) (fuel : Nat) (s : TraversalState)
    (h : traversalCost paths s ≤ fuel) : (traversal c paths actor fuel s).queue = [] := by
  induction fuel generalizing s with
  | zero =>
    simp only [traversal]
    apply List.length_eq_zero_iff.mp
    simp only [traversalCost] at h
    omega
  | succ fuel ih =>
    cases hq : s.queue with
    | nil => simp [traversal,hq]
    | cons req queue =>
      have hd := traversalStep_decreases c paths actor s (by simp [hq])
      have hb : traversalCost paths (traversalStep c paths actor s) ≤ fuel := by omega
      simpa only [traversal,hq] using ih _ hb

#print axioms pendingCost_add_le
#print axioms pendingCost_pays
#print axioms partnerFor_some
#print axioms traversalStep_decreases
#print axioms traversal_drains
end Authority
