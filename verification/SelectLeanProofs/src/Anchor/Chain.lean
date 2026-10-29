import Anchor.Verifier

namespace Anchor

def Ordered (anchors : List Submission) : Prop :=
  anchors.Pairwise (fun newer older => Prefix older.history newer.history)

def Bound (anchors : List Submission) : Prop :=
  ∀ x ∈ anchors, binding x = true

theorem prefixOK_iff (old next : Submission) :
    prefixOK old next = true ↔ Prefix old.history next.history := by
  simp [prefixOK]

theorem binding_position (x : Submission) (h : binding x = true) :
    x.statement.head.position + 1 = x.history.length := by
  unfold binding at h
  split at h <;> simp_all

theorem valid_binding (scope : Scope) (evidenceOK : EvidenceOK) (x : Submission)
    (h : valid scope evidenceOK x = true) : binding x = true := by
  simp only [valid, Bool.and_eq_true] at h
  exact h.1.2

theorem accept_unchanged_or_insert (scope : Scope) (digest : Statement → Digest)
    (evidenceOK : EvidenceOK) (anchors : List Submission) (x : Submission) :
    (accept scope digest evidenceOK anchors x).anchors = anchors ∨
    ((accept scope digest evidenceOK anchors x).anchors = x :: anchors ∧
      valid scope evidenceOK x = true ∧
      ∀ old rest, anchors = old :: rest → Prefix old.history x.history) := by
  unfold accept
  split
  · exact Or.inl rfl
  split
  · exact Or.inl rfl
  split
  · exact Or.inl rfl
  rename_i hv
  cases anchors with
  | nil =>
    dsimp only
    split
    · exact Or.inr ⟨rfl, by simpa using hv, by simp⟩
    · exact Or.inl rfl
  | cons old rest =>
    dsimp only
    split
    · exact Or.inl rfl
    split
    · exact Or.inl rfl
    rename_i hp
    apply Or.inr
    refine ⟨rfl, by simpa using hv, ?_⟩
    intro a tail heq
    cases heq
    simpa [prefixOK] using hp

theorem accept_ordered (scope : Scope) (digest : Statement → Digest)
    (evidenceOK : EvidenceOK) (anchors : List Submission) (x : Submission)
    (h : Ordered anchors) : Ordered (accept scope digest evidenceOK anchors x).anchors := by
  rcases accept_unchanged_or_insert scope digest evidenceOK anchors x with heq | ⟨heq, _, hp⟩
  · simpa [heq] using h
  rw [heq]
  apply List.pairwise_cons.mpr
  refine ⟨?_, h⟩
  intro a ha
  cases anchors with
  | nil => simp at ha
  | cons old rest =>
    have ext := hp old rest rfl
    rcases List.mem_cons.mp ha with rfl | ha
    · exact ext
    · exact ((List.pairwise_cons.mp h).1 a ha).trans ext

theorem accept_bound (scope : Scope) (digest : Statement → Digest)
    (evidenceOK : EvidenceOK) (anchors : List Submission) (x : Submission)
    (h : Bound anchors) : Bound (accept scope digest evidenceOK anchors x).anchors := by
  rcases accept_unchanged_or_insert scope digest evidenceOK anchors x with heq | ⟨heq, hv, _⟩
  · simpa [heq] using h
  rw [heq]
  intro a ha
  rcases List.mem_cons.mp ha with rfl | ha
  · exact valid_binding scope evidenceOK a hv
  · exact h a ha

theorem step_ordered (scope : Scope) (digest : Statement → Digest)
    (evidenceOK : EvidenceOK) (state : State) (x : Submission)
    (h : Ordered state.anchors) : Ordered (step scope digest evidenceOK state x).state.anchors :=
  accept_ordered scope digest evidenceOK state.anchors x h

theorem run_ordered (scope : Scope) (digest : Statement → Digest)
    (evidenceOK : EvidenceOK) (state : State) (inputs : List Submission)
    (h : Ordered state.anchors) : Ordered (run scope digest evidenceOK state inputs).anchors := by
  induction inputs generalizing state with
  | nil => exact h
  | cons x xs ih => exact ih _ (step_ordered scope digest evidenceOK state x h)

theorem run_bound (scope : Scope) (digest : Statement → Digest)
    (evidenceOK : EvidenceOK) (state : State) (inputs : List Submission)
    (h : Bound state.anchors) : Bound (run scope digest evidenceOK state inputs).anchors := by
  induction inputs generalizing state with
  | nil => exact h
  | cons x xs ih => exact ih _ (accept_bound scope digest evidenceOK state.anchors x h)

theorem initial_run_ordered (scope : Scope) (digest : Statement → Digest)
    (evidenceOK : EvidenceOK) (inputs : List Submission) :
    Ordered (run scope digest evidenceOK {} inputs).anchors :=
  run_ordered scope digest evidenceOK {} inputs (by simp [Ordered])

theorem initial_run_bound (scope : Scope) (digest : Statement → Digest)
    (evidenceOK : EvidenceOK) (inputs : List Submission) :
    Bound (run scope digest evidenceOK {} inputs).anchors :=
  run_bound scope digest evidenceOK {} inputs (by simp [Bound])

end Anchor

namespace Anchor

theorem ordered_comparable (anchors : List Submission) (h : Ordered anchors)
    (a b : Submission) (ha : a ∈ anchors) (hb : b ∈ anchors) :
    Prefix a.history b.history ∨ Prefix b.history a.history := by
  induction anchors with
  | nil => simp at ha
  | cons first tail ih =>
    have hp := List.pairwise_cons.mp h
    rcases List.mem_cons.mp ha with haf | hat
    · subst a
      rcases List.mem_cons.mp hb with hbf | hbt
      · subst b
        exact Or.inl List.prefix_rfl
      · exact Or.inr (hp.1 b hbt)
    · rcases List.mem_cons.mp hb with hbf | hbt
      · subst b
        exact Or.inl (hp.1 a hat)
      · exact ih hp.2 hat hbt

theorem same_position_same_prefix (anchors : List Submission)
    (h : Ordered anchors) (bound : Bound anchors) (a b : Submission)
    (ha : a ∈ anchors) (hb : b ∈ anchors)
    (same : a.statement.head.position = b.statement.head.position) : a.history = b.history := by
  have al := binding_position a (bound a ha)
  have bl := binding_position b (bound b hb)
  have len : a.history.length = b.history.length := by omega
  rcases ordered_comparable anchors h a b ha hb with hp | hp
  · exact hp.eq_of_length len
  · exact (hp.eq_of_length len.symm).symm

theorem no_fork_after_run (scope : Scope) (digest : Statement → Digest)
    (evidenceOK : EvidenceOK) (inputs : List Submission)
    (a b : Submission) (ha : a ∈ (run scope digest evidenceOK {} inputs).anchors)
    (hb : b ∈ (run scope digest evidenceOK {} inputs).anchors) :
    Prefix a.history b.history ∨ Prefix b.history a.history :=
  ordered_comparable _ (initial_run_ordered scope digest evidenceOK inputs) a b ha hb

theorem same_position_after_run (scope : Scope) (digest : Statement → Digest)
    (evidenceOK : EvidenceOK) (inputs : List Submission)
    (a b : Submission) (ha : a ∈ (run scope digest evidenceOK {} inputs).anchors)
    (hb : b ∈ (run scope digest evidenceOK {} inputs).anchors)
    (same : a.statement.head.position = b.statement.head.position) : a.history = b.history :=
  same_position_same_prefix _ (initial_run_ordered scope digest evidenceOK inputs)
    (initial_run_bound scope digest evidenceOK inputs) a b ha hb same

theorem ordered_no_rollback (newer older : Submission) (rest : List Submission)
    (h : Ordered (newer :: older :: rest)) (bound : Bound (newer :: older :: rest)) :
    older.statement.head.position ≤ newer.statement.head.position := by
  have hp := (List.pairwise_cons.mp h).1 older (by simp)
  have hn := binding_position newer (bound newer (by simp))
  have ho := binding_position older (bound older (by simp))
  have hl := hp.length_le
  omega

end Anchor

#print axioms Anchor.prefixOK_iff
#print axioms Anchor.binding_position
#print axioms Anchor.valid_binding
#print axioms Anchor.accept_unchanged_or_insert
#print axioms Anchor.accept_ordered
#print axioms Anchor.accept_bound
#print axioms Anchor.step_ordered
#print axioms Anchor.run_ordered
#print axioms Anchor.run_bound
#print axioms Anchor.initial_run_ordered
#print axioms Anchor.initial_run_bound
#print axioms Anchor.ordered_comparable
#print axioms Anchor.same_position_same_prefix
#print axioms Anchor.no_fork_after_run
#print axioms Anchor.same_position_after_run
#print axioms Anchor.ordered_no_rollback
