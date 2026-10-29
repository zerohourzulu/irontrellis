import G65.NonExpansion
namespace Authority.G65
open Authority.G64

/-- Only the two outcome constructors produced by the algebra can enter this
    equivalence. A caller-provided indeterminate code is not an authority fact. -/
theorem finalize_projection (c : Corpus) (d : Decision)
    (shape : (∃ a, d = .allow a) ∨ (∃ fs, d = .deny fs)) :
    revisedAllow (finalize c d) = allows d := by
  rcases shape with ⟨a,rfl⟩ | ⟨fs,rfl⟩
  · simp only [finalize,allows]; split <;> rfl
  · rfl

theorem algebra_shape (ledger : List Usage) (c : Corpus) (paths : List Path)
    (r : Request) (t : Nat) (admin : Path → Bool) :
    (∃ a, evaluateAlgebra ledger c paths r t admin = .allow a) ∨
    (∃ fs, evaluateAlgebra ledger c paths r t admin = .deny fs) := by
  unfold evaluateAlgebra
  split
  · exact Or.inr ⟨_,rfl⟩
  · dsimp only
    split
    · exact Or.inl ⟨_,rfl⟩
    · split <;> exact Or.inr ⟨_,rfl⟩

theorem afterNonce_shape (collision : Bool) (d : Decision)
    (shape : (∃ a, d = .allow a) ∨ (∃ fs, d = .deny fs)) :
    (∃ a, afterNonce collision d = .allow a) ∨
    (∃ fs, afterNonce collision d = .deny fs) := by
  rcases shape with ⟨a,rfl⟩ | ⟨fs,rfl⟩
  · cases collision
    · exact Or.inl ⟨a,rfl⟩
    · exact Or.inr ⟨_,rfl⟩
  · exact Or.inr ⟨fs,rfl⟩

theorem afterNonce_allows (collision : Bool) (d : Decision) :
    allows (afterNonce collision d) = (allows d && !collision) := by
  cases collision <;> cases d <;> rfl

def finalDecision (ledger : List Usage) (c : Corpus) (paths : List Path)
    (r : Request) (t : Nat) (collision : Bool) (admin : Path → Bool := fun _ => true) : Decision :=
  finalize c (afterNonce collision (evaluateAlgebra ledger c paths r t admin))

/-- A-133's after-nonce, before-preflight meaning on this actual component.
    Binding, budget, capture, cryptography and history validity are not here. -/
theorem revised_allow_exact (ledger : List Usage) (c : Corpus) (paths : List Path)
    (r : Request) (t : Nat) (collision : Bool) (admin : Path → Bool) :
    revisedAllow (finalDecision ledger c paths r t collision admin) =
      (allows (evaluateAlgebra ledger c paths r t admin) && !collision) := by
  unfold finalDecision
  rw [finalize_projection c _ (afterNonce_shape collision _ (algebra_shape ledger c paths r t admin))]
  exact afterNonce_allows _ _

theorem revised_allow_nonexpansion (ledger : List Usage) (c : Corpus) (paths : List Path)
    (target : Id) (guard : terminationGuard c paths target = true)
    (r : Request) (t : Nat) (collision : Bool) (admin : Path → Bool)
    (success : revisedAllow (finalDecision ledger (terminate c target) paths r t collision admin) = true) :
    revisedAllow (finalDecision ledger c paths r t collision admin) = true := by
  rw [revised_allow_exact] at success ⊢
  have parts : allows (evaluateAlgebra ledger (terminate c target) paths r t admin) = true ∧ (!collision) = true := by
    simpa only [Bool.and_eq_true] using success
  cases afterEq : evaluateAlgebra ledger (terminate c target) paths r t admin with
  | deny fs => simp [afterEq,allows] at parts
  | indeterminate code => simp [afterEq,allows] at parts
  | allow a =>
    obtain ⟨before,beforeEq⟩ := algebra_nonexpansion ledger c paths target guard r t admin a afterEq
    simp only [beforeEq,allows,Bool.true_and]
    exact parts.2

theorem own_reservation_does_not_collide (actor nonce intent : Id) (admitted : Bool) :
    nonceCollision [{actorId := actor,nonce := nonce,intentId := intent,admitted := admitted}]
      actor nonce intent = false := by
  simp [nonceCollision]

theorem different_unadmitted_reservation_collides :
    nonceCollision [{actorId := "A",nonce := "n",intentId := "other",admitted := false}]
      "A" "n" "current" = true := by decide

#print axioms finalize_projection
#print axioms algebra_shape
#print axioms afterNonce_shape
#print axioms afterNonce_allows
#print axioms revised_allow_exact
#print axioms revised_allow_nonexpansion
#print axioms own_reservation_does_not_collide
#print axioms different_unadmitted_reservation_collides
end Authority.G65
