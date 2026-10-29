import AuthorityModel.Fold
namespace Authority

/-- Instrumentation of the existing executable traversal; no policy changes. -/
structure TraversalState where
  seen : List Id
  queue : List Requirement
  graph : Graph

def partnerFor (c : Corpus) (paths : List Path) (actor id : Id) : Option Path :=
  match paths.find? (fun p => p.terminal.authorityId == id) with
  | none => none
  | some p => if (recognize c p).isNone || p.independent || p.terminal.granteeId != actor then none else some p

def traversalStep (c : Corpus) (paths : List Path) (actor : Id) (s : TraversalState) : TraversalState :=
  match s.queue with
  | [] => s
  | req :: queue =>
    let graph := { s.graph with requirements := s.graph.requirements ++ [req] }
    if s.seen.contains req.requiredId then ⟨s.seen, queue, graph⟩
    else match partnerFor c paths actor req.requiredId with
      | none => ⟨req.requiredId :: s.seen, queue, { graph with missing := req.requiredId :: graph.missing }⟩
      | some p => ⟨req.requiredId :: s.seen, queue ++ directRequirements p, { graph with partners := graph.partners ++ [p] }⟩

def traversal (c : Corpus) (paths : List Path) (actor : Id) : Nat → TraversalState → TraversalState
  | 0, s => s
  | fuel+1, s => match s.queue with
    | [] => s
    | _::_ => traversal c paths actor fuel (traversalStep c paths actor s)

def finishTraversal (s : TraversalState) : Graph :=
  { s.graph with missing := s.graph.missing ++ s.queue.map (·.requiredId) }

theorem traversal_refines_selectLoop (c : Corpus) (paths : List Path) (actor : Id)
    (fuel : Nat) (seen : List Id) (queue : List Requirement) (graph : Graph) :
    finishTraversal (traversal c paths actor fuel ⟨seen, queue, graph⟩) = selectLoop c paths actor fuel seen queue graph := by
  induction fuel generalizing seen queue graph with
  | zero => cases queue <;> simp [traversal, finishTraversal, selectLoop]
  | succ fuel ih =>
    cases queue with
    | nil => simp [traversal, finishTraversal, selectLoop]
    | cons req queue =>
      simp only [traversal, traversalStep, selectLoop]
      cases hs : seen.contains req.requiredId
      · simp only [Bool.false_eq_true, ↓reduceIte]
        unfold partnerFor
        cases hp : paths.find? (fun p => p.terminal.authorityId == req.requiredId) with
        | none => simpa only [hp] using ih (req.requiredId :: seen) queue { graph with requirements := graph.requirements ++ [req], missing := req.requiredId :: graph.missing }
        | some p =>
          cases he : (recognize c p).isNone || p.independent || p.terminal.granteeId != actor
          · simpa only [hp, he, Bool.false_eq_true, ↓reduceIte] using ih (req.requiredId :: seen) (queue ++ directRequirements p) { graph with requirements := graph.requirements ++ [req], partners := graph.partners ++ [p] }
          · simpa only [hp, he, ↓reduceIte] using ih (req.requiredId :: seen) queue { graph with requirements := graph.requirements ++ [req], missing := req.requiredId :: graph.missing }
      · simpa only [hs, ↓reduceIte] using ih seen queue { graph with requirements := graph.requirements ++ [req] }

/-- Semantic requirements use every grant's declared set, not traversal output. -/
def PathRequires (p : Path) (id : Id) : Prop :=
  ∃ grant ∈ p.grants, id ∈ grant.constraints.requiredIntersectionIds

theorem direct_aux_sound (previous : List Id) (gs : List Permission) (req : Requirement)
    (h : req ∈ directRequirementsAux previous gs) :
    ∃ grant ∈ gs, req.requiredId ∈ grant.constraints.requiredIntersectionIds := by
  induction gs generalizing previous with
  | nil => simp [directRequirementsAux] at h
  | cons g gs ih =>
    simp only [directRequirementsAux, List.mem_append] at h
    rcases h with h | h
    · simp only [List.mem_map, List.mem_filter] at h
      obtain ⟨id, ⟨hid, _⟩, he⟩ := h
      cases he
      exact ⟨g, by simp, hid⟩
    · obtain ⟨grant, hg, hr⟩ := ih _ h
      exact ⟨grant, by simp [hg], hr⟩

theorem direct_aux_covers (previous : List Id) (gs : List Permission) (id : Id)
    (h : ∃ grant ∈ gs, id ∈ grant.constraints.requiredIntersectionIds) :
    id ∈ previous ∨ ∃ req ∈ directRequirementsAux previous gs, req.requiredId = id := by
  induction gs generalizing previous with
  | nil => simp at h
  | cons g gs ih =>
    by_cases hprev : id ∈ previous
    · exact Or.inl hprev
    · right
      have front (hg : id ∈ g.constraints.requiredIntersectionIds) :
          ∃ req ∈ directRequirementsAux previous (g::gs), req.requiredId = id := by
        refine ⟨⟨id,g.authorityId⟩, ?_, rfl⟩
        simp only [directRequirementsAux, List.mem_append, List.mem_map, List.mem_filter]
        exact Or.inl ⟨id, ⟨hg, by simpa using hprev⟩, rfl⟩
      obtain ⟨grant, hg, hr⟩ := h
      simp only [List.mem_cons] at hg
      rcases hg with hsame | hg
      · subst grant; exact front hr
      · rcases ih g.constraints.requiredIntersectionIds ⟨grant,hg,hr⟩ with hfront | hrest
        · exact front hfront
        · obtain ⟨req,hreq,he⟩ := hrest
          exact ⟨req, List.mem_append_right _ hreq, he⟩

theorem direct_requirements_iff (p : Path) (id : Id) :
    (∃ req ∈ directRequirements p, req.requiredId = id) ↔ PathRequires p id := by
  constructor
  · rintro ⟨req,hr,rfl⟩; exact direct_aux_sound _ _ _ hr
  · intro h
    rcases direct_aux_covers [] p.grants id h with hnil | hr
    · simp at hnil
    · exact hr

#print axioms traversal_refines_selectLoop
#print axioms direct_aux_sound
#print axioms direct_aux_covers
#print axioms direct_requirements_iff
end Authority
