import AuthorityModel.Eligibility
namespace Authority

theorem partnerFor_none_iff_no_eligible (c : Corpus) (paths : List Path) (hv : validateCorpus c = .ok paths)
    (actor id : Id) : partnerFor c paths actor id = none ↔ ¬∃ p, EligiblePartner c actor id p := by
  constructor
  · intro hn ⟨p,hp⟩
    have hs := (partnerFor_iff_eligible c paths hv actor id p).mpr hp
    rw [hn] at hs; contradiction
  · intro hn
    cases hs : partnerFor c paths actor id with
    | none => rfl
    | some p => exact False.elim (hn ⟨p,(partnerFor_iff_eligible c paths hv actor id p).mp hs⟩)

def ExactSemanticGraph (c : Corpus) (main : Path) (actor : Id) (graph : Graph) : Prop :=
  (∀ p, p ∈ graph.partners ↔ ∃ id, SemanticRequired c main actor id ∧ EligiblePartner c actor id p) ∧
  (∀ id, id ∈ graph.missing ↔ SemanticRequired c main actor id ∧ ¬∃ p, EligiblePartner c actor id p)

theorem drained_semantic_graph (c : Corpus) (paths : List Path) (main : Path) (actor : Id)
    (hv : validateCorpus c = .ok paths)
    (hq : (traversal c paths actor ((c.permissions.length+1)*1024+1)
      ⟨[],directRequirements main,{ main := main }⟩).queue = []) :
    ExactSemanticGraph c main actor (selectGraph c paths main actor) := by
  have h := selectGraph_exact_of_drained c paths main actor hq
  simpa only [ExactSemanticGraph, reachable_iff_semantic c paths hv, partnerFor_iff_eligible c paths hv,
    partnerFor_none_iff_no_eligible c paths hv] using h

/-- Actual selectGraph computes exactly the least semantic closure on bounded
    validated corpora, including both present partners and unavailable IDs. -/
theorem selectGraph_exact_semantic (c : Corpus) (paths : List Path) (main : Path) (actor : Id)
    (hc : corpusStatus c = .valid) (hv : validateCorpus c = .ok paths) (hm : main ∈ paths) :
    ExactSemanticGraph c main actor (selectGraph c paths main actor) :=
  drained_semantic_graph c paths main actor hv (selectGraph_fuel_sufficient c paths main actor hc hv hm)

/-- Even outside typed capture bounds, a result with no missing IDs contains
    exactly its semantic closure; fail-closed exhaustion cannot certify a prefix. -/
theorem selectGraph_no_missing_exact (c : Corpus) (paths : List Path) (main : Path) (actor : Id)
    (hv : validateCorpus c = .ok paths) (hm : (selectGraph c paths main actor).missing = []) :
    ExactSemanticGraph c main actor (selectGraph c paths main actor) :=
  drained_semantic_graph c paths main actor hv (selectGraph_no_missing_drains c paths main actor hm)

/-- Every ALLOW from the actual state entry has the complete least dependency
    graph. No caller-provided graph or corpus-bound premise is required here. -/
theorem authorizeState_complete_graph (s : State) (i : Input) (a : Candidate)
    (h : authorizeState s i = .allow a) :
    ExactSemanticGraph s.corpus a.graph.main i.request.actorId a.graph := by
  obtain ⟨paths,hv,ha⟩ := authorizeState_allow_validated s i a h
  obtain ⟨main,_,_,_,hc⟩ := algebra_allow_origin s.corpus paths i.request i.evaluationTime _ a ha
  have he := candidate_success_graph _ _ _ _ _ _ _ hc
  have hm := candidate_success_no_missing _ _ _ _ _ _ _ hc
  rw [he] at hm
  have hx := selectGraph_no_missing_exact s.corpus paths main i.request.actorId hv hm
  rw [he,selectGraph_preserves_main]
  exact hx

theorem authorizeState_every_required_partner (s : State) (i : Input) (a : Candidate)
    (h : authorizeState s i = .allow a) (id : Id)
    (hr : SemanticRequired s.corpus a.graph.main i.request.actorId id) :
    ∃ p, EligiblePartner s.corpus i.request.actorId id p ∧ p ∈ a.graph.partners := by
  have hx := authorizeState_complete_graph s i a h
  obtain ⟨paths,hv,ha⟩ := authorizeState_allow_validated s i a h
  obtain ⟨main,_,_,_,hc⟩ := algebra_allow_origin s.corpus paths i.request i.evaluationTime _ a ha
  have hm := candidate_success_no_missing _ _ _ _ _ _ _ hc
  by_cases he : ∃ p, EligiblePartner s.corpus i.request.actorId id p
  · obtain ⟨p,hp⟩ := he
    exact ⟨p,hp,(hx.1 p).mpr ⟨id,hr,hp⟩⟩
  · have hbad := (hx.2 id).mpr ⟨hr,he⟩
    simp [hm] at hbad

/-- The executable final fold narrows every grant on every semantically
    required partner, through arbitrarily many transitive dependency steps. -/
theorem authorizeState_final_fold_every_required_grant (s : State) (i : Input) (a : Candidate)
    (h : authorizeState s i = .allow a) (id : Id)
    (hr : SemanticRequired s.corpus a.graph.main i.request.actorId id) :
    ∃ p, EligiblePartner s.corpus i.request.actorId id p ∧ p ∈ a.graph.partners ∧
      ∀ grant ∈ p.grants, Refines (combineConstraints a.graph.grants) grant.constraints := by
  obtain ⟨p,hp,hin⟩ := authorizeState_every_required_partner s i a h id hr
  refine ⟨p,hp,hin,?_⟩
  intro grant hg
  exact combined_graph_refines_path_grant a.graph p grant (by simp [Graph.paths,hin]) hg

/-- Universal form: eligibility identifies the exact selected path, so every
    eligible path for a reachable required ID contributes its full ancestry. -/
theorem authorizeState_final_fold_required_path (s : State) (i : Input) (a : Candidate)
    (h : authorizeState s i = .allow a) (id : Id) (p : Path)
    (hr : SemanticRequired s.corpus a.graph.main i.request.actorId id)
    (hp : EligiblePartner s.corpus i.request.actorId id p) (grant : Permission) (hg : grant ∈ p.grants) :
    Refines (combineConstraints a.graph.grants) grant.constraints := by
  have hmem := ((authorizeState_complete_graph s i a h).1 p).mpr ⟨id,hr,hp⟩
  exact combined_graph_refines_path_grant a.graph p grant (by simp [Graph.paths,hmem]) hg

#print axioms partnerFor_none_iff_no_eligible
#print axioms drained_semantic_graph
#print axioms selectGraph_exact_semantic
#print axioms selectGraph_no_missing_exact
#print axioms authorizeState_complete_graph
#print axioms authorizeState_every_required_partner
#print axioms authorizeState_final_fold_every_required_grant
#print axioms authorizeState_final_fold_required_path
end Authority
