import AuthorityModel.Authority
namespace Authority.G64

/-- A-127.2 quantifies every unrevoked prohibition, without an activity filter.
    The path list is the actual validateCorpus result. -/
def anchorPath (paths : List Path) (p : Prohibition) : Option Path :=
  p.parentAuthorityId.bind fun id => paths.find? (fun q => q.terminal.authorityId == id)
def pathMentions (path : Path) (id : Id) : Bool :=
  path.grants.any fun g => g.grantorId == id || g.granteeId == id
def prohibitionMentions (paths : List Path) (p : Prohibition) (id : Id) : Bool :=
  p.grantorId == id || (anchorPath paths p).any (fun path => pathMentions path id)
def terminationGuard (c : Corpus) (paths : List Path) (id : Id) : Bool :=
  (c.agents.getD []).any (fun a => a.id == id && !a.terminated) &&
  !c.prohibitions.any (fun p => !c.revoked.contains p.authorityId && prohibitionMentions paths p id)
def prTermination (c : Corpus) (id : Id) : Bool :=
  match validateCorpus c with | .error _ => false | .ok paths => terminationGuard c paths id
def oldTerminationGuard (c : Corpus) (id : Id) : Bool :=
  (c.agents.getD []).any (fun a => a.id == id && !a.terminated) &&
  !c.prohibitions.any (fun p => !c.revoked.contains p.authorityId && p.grantorId == id)
def terminateAgent (id : Id) (a : Agent) : Agent :=
  if a.id == id then { a with terminated := true } else a
def terminate (c : Corpus) (id : Id) : Corpus :=
  { c with agents := c.agents.map (fun agents => agents.map (terminateAgent id)) }

theorem terminate_agent_id (id : Id) (a : Agent) : (terminateAgent id a).id = a.id := by
  unfold terminateAgent; split <;> rfl

theorem find_terminated (agents : List Agent) (target id : Id) :
    (agents.map (terminateAgent target)).find? (fun a => a.id == id) =
      (agents.find? (fun a => a.id == id)).map (terminateAgent target) := by
  induction agents with
  | nil => rfl
  | cons a rest ih =>
    simp only [List.map_cons,List.find?_cons,terminate_agent_id]
    cases h : a.id == id <;> simp [ih]

theorem inactive_unchanged (c : Corpus) (target id : Id) (different : id ≠ target) :
    inactive (terminate c target) id = inactive c id := by
  unfold inactive terminate
  cases agents : c.agents with
  | none => rfl
  | some xs =>
    simp only [Option.map_some,Option.getD_some,find_terminated]
    cases found : xs.find? (fun a => a.id == id) with
    | none => rfl
    | some a =>
      have key : a.id = id := by simpa using List.find?_some found
      simp [terminateAgent,key,different]

theorem all_congr_mem (xs : List α) (p q : α → Bool) (equal : ∀ x ∈ xs, p x = q x) :
    xs.all p = xs.all q := by
  induction xs with
  | nil => rfl
  | cons x rest ih =>
    simp only [List.all_cons,equal x (by simp),ih (by intro y mem; exact equal y (by simp [mem]))]

theorem path_unchanged (c : Corpus) (path : Path) (target : Id)
    (avoids : pathMentions path target = false) (t : Nat) :
    pathActive (terminate c target) path t = pathActive c path t := by
  have each : ∀ g ∈ path.grants, g.grantorId ≠ target ∧ g.granteeId ≠ target := by
    simpa [pathMentions,List.any_eq_false] using avoids
  unfold pathActive
  apply all_congr_mem
  intro g member
  rw [inactive_unchanged c target g.grantorId (each g member).1,
      inactive_unchanged c target g.granteeId (each g member).2]
  rfl

theorem guard_excludes (c : Corpus) (paths : List Path) (target : Id)
    (guard : terminationGuard c paths target = true) (p : Prohibition)
    (member : p ∈ c.prohibitions) (unrevoked : c.revoked.contains p.authorityId = false) :
    prohibitionMentions paths p target = false := by
  simp only [terminationGuard,Bool.and_eq_true] at guard
  have absent : c.prohibitions.any (fun p => !c.revoked.contains p.authorityId && prohibitionMentions paths p target) = false := by simpa using guard.2
  have no := List.any_eq_false.mp absent p member
  apply Bool.eq_false_iff.mpr
  simpa only [unrevoked,Bool.not_false,Bool.true_and] using no

theorem guard_preserves_prohibition_activity (c : Corpus) (paths : List Path) (target : Id)
    (guard : terminationGuard c paths target = true) (p : Prohibition)
    (member : p ∈ c.prohibitions) (t : Nat) :
    prohibitionActive (terminate c target) paths p t = prohibitionActive c paths p t := by
  by_cases revoked : c.revoked.contains p.authorityId = true
  · simp only [prohibitionActive,terminate,revoked,Bool.not_true,Bool.false_and]
  · have unrevoked : c.revoked.contains p.authorityId = false := Bool.eq_false_iff.mpr revoked
    have excludes := guard_excludes c paths target guard p member unrevoked
    have noAnchor := (Bool.or_eq_false_iff.mp excludes).2
    unfold prohibitionActive
    dsimp only [terminate]
    congr 1
    split
    · rfl
    · cases parent : p.parentAuthorityId with
      | none => rfl
      | some id =>
        cases found : paths.find? (fun q => q.terminal.authorityId == id) with
        | none => simp only [found,Option.any_none]
        | some path =>
          have avoids : pathMentions path target = false := by simpa [anchorPath,parent,found] using noAnchor
          simpa only [terminate,found,Option.any_some] using path_unchanged c path target avoids t

#print axioms terminate_agent_id
#print axioms find_terminated
#print axioms inactive_unchanged
#print axioms all_congr_mem
#print axioms path_unchanged
#print axioms guard_excludes
#print axioms guard_preserves_prohibition_activity
end Authority.G64
