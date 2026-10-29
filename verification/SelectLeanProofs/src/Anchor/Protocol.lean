import Anchor.Chain

namespace Anchor

theorem accept_duplicate (scope : Scope) (digest : Statement → Digest)
    (evidenceOK : EvidenceOK) (anchors : List Submission) (x old : Submission)
    (mem : old ∈ anchors) (same : old.statement = x.statement) :
    accept scope digest evidenceOK anchors x = ⟨.duplicate, anchors⟩ := by
  have h : anchors.any (fun old => decide (old.statement = x.statement)) = true := by
    simp only [List.any_eq_true]
    exact ⟨old, mem, by simp [same]⟩
  simp [accept, h]

theorem accept_success (scope : Scope) (digest : Statement → Digest)
    (evidenceOK : EvidenceOK) (anchors : List Submission) (x : Submission)
    (h : (accept scope digest evidenceOK anchors x).status = .accepted) :
    (accept scope digest evidenceOK anchors x).anchors = x :: anchors ∧
    valid scope evidenceOK x = true ∧
    (match anchors with
     | [] => x.statement.sequence = 0
     | old :: _ => link digest old.statement x.statement = true ∧ prefixOK old x = true) := by
  cases anchors <;> unfold accept at h ⊢ <;>
    repeat' first | split at h <;> simp_all | simp_all
  all_goals grind

theorem rejected_retains_anchors (scope : Scope) (digest : Statement → Digest)
    (evidenceOK : EvidenceOK) (anchors : List Submission) (x : Submission)
    (h : (accept scope digest evidenceOK anchors x).status ≠ .accepted) :
    (accept scope digest evidenceOK anchors x).anchors = anchors := by
  cases anchors <;> unfold accept at h ⊢ <;>
    repeat' first | split at h <;> simp_all | simp_all
  all_goals grind

theorem accepted_link_exact (scope : Scope) (digest : Statement → Digest)
    (evidenceOK : EvidenceOK) (old : Submission) (rest : List Submission) (x : Submission)
    (h : (accept scope digest evidenceOK (old :: rest) x).status = .accepted) :
    x.statement.sequence = old.statement.sequence + 1 ∧
    x.statement.predecessor = some (digest old.statement) ∧
    x.statement.previousHead = some old.statement.head.short := by
  have hs := (accept_success scope digest evidenceOK (old :: rest) x h).2.2.1
  simpa [link] using hs

theorem accepted_prefix_exact (scope : Scope) (digest : Statement → Digest)
    (evidenceOK : EvidenceOK) (old : Submission) (rest : List Submission) (x : Submission)
    (h : (accept scope digest evidenceOK (old :: rest) x).status = .accepted) :
    Prefix old.history x.history :=
  (prefixOK_iff old x).mp (accept_success scope digest evidenceOK (old :: rest) x h).2.2.2

theorem fork_refused (scope : Scope) (digest : Statement → Digest)
    (evidenceOK : EvidenceOK) (old : Submission) (rest : List Submission) (x : Submission)
    (fork : ¬ Prefix old.history x.history) :
    (accept scope digest evidenceOK (old :: rest) x).status ≠ .accepted := by
  intro h
  exact fork (accepted_prefix_exact scope digest evidenceOK old rest x h)

theorem rollback_refused (scope : Scope) (digest : Statement → Digest)
    (evidenceOK : EvidenceOK) (old : Submission) (rest : List Submission) (x : Submission)
    (boundOld : binding old = true) (back : x.statement.head.position < old.statement.head.position) :
    (accept scope digest evidenceOK (old :: rest) x).status ≠ .accepted := by
  intro h
  have hp := accepted_prefix_exact scope digest evidenceOK old rest x h
  have hn := binding_position x (valid_binding scope evidenceOK x
    (accept_success scope digest evidenceOK (old :: rest) x h).2.1)
  have ho := binding_position old boundOld
  have hl := hp.length_le
  omega

theorem accepted_binding_and_primitive (scope : Scope) (digest : Statement → Digest)
    (evidenceOK : EvidenceOK) (anchors : List Submission) (x : Submission)
    (h : (accept scope digest evidenceOK anchors x).status = .accepted) :
    x.statement.scope = scope ∧ shape x.statement = true ∧ binding x = true ∧
      evidenceOK x.statement x.history = true := by
  have hv := (accept_success scope digest evidenceOK anchors x h).2.1
  simpa only [valid, Bool.and_eq_true, decide_eq_true_eq, and_assoc] using hv

/-- An injective modeled digest identifies the referenced statement. The
    hypothesis is local mathematical injectivity, not a theorem about SHA. -/
theorem unique_digest_reference (digest : Statement → Digest)
    (injective : Function.Injective digest) (a b : Statement)
    (same : digest a = digest b) : a = b := injective same

end Anchor

#print axioms Anchor.accept_duplicate
#print axioms Anchor.accept_success
#print axioms Anchor.rejected_retains_anchors
#print axioms Anchor.accepted_link_exact
#print axioms Anchor.accepted_prefix_exact
#print axioms Anchor.fork_refused
#print axioms Anchor.rollback_refused
#print axioms Anchor.accepted_binding_and_primitive
#print axioms Anchor.unique_digest_reference
