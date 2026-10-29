import Termination.TerminationNonExpansion
namespace Authority.G64.Witnesses
set_option maxRecDepth 1000000
set_option maxHeartbeats 0
set_option cbv.maxSteps 5000000

def cns : Constraints := { actions := ["read"], resources := ["r"], maxDelegationDepth := 2 }
def rootGrant : Permission := { authorityId := "a-main", grantorId := "P", granteeId := "B", rootAuthorityId := "a-main", constraints := cns }
def child : Permission := { authorityId := "a-child", grantorId := "B", granteeId := "A", rootAuthorityId := "a-main", parentAuthorityId := some "a-main", constraints := {cns with maxDelegationDepth := 1} }
def fallback : Permission := { authorityId := "z-fallback", grantorId := "P", granteeId := "A", rootAuthorityId := "z-fallback", constraints := cns }
def mainPath : Path := { grants := [rootGrant,child] }
def fallbackPath : Path := { grants := [fallback] }
def paths : List Path := [{grants := [rootGrant]},mainPath,fallbackPath]
def base : Corpus := {
  permissions := [rootGrant,child,fallback]
  roots := [
    {rootAuthorityId := "a-main",principalId := "P",principalRecognitionEventId := "p",rootGrantEventId := "e-main"},
    {rootAuthorityId := "z-fallback",principalId := "P",principalRecognitionEventId := "p",rootGrantEventId := "e-fallback"}]
  evidence := [
    {authorityId := "a-main",grantEventId := "e-main",grantEventPosition := 4},
    {authorityId := "a-child",grantEventId := "e-child",grantEventPosition := 5},
    {authorityId := "z-fallback",grantEventId := "e-fallback",grantEventPosition := 6}]
  agents := some [{id := "A",principalId := "P",controllerId := "controller"},
    {id := "B",principalId := "P",controllerId := "controller"}]
  principals := some [{id := "P",creationEventId := "p"}] }
def ban : Prohibition := {
  authorityId := "ban",grantorId := "A",scope := .ROOT
  rootAuthorityId := some "a-main",parentAuthorityId := some "a-child"
  constraints := {cns with maxDelegationDepth := 0} }
def banCorpus : Corpus := {base with
  prohibitions := [ban]
  evidence := base.evidence ++ [{authorityId := "ban",grantEventId := "e-ban",grantEventPosition := 7}]}

theorem ancestor_witness_valid : corpusStatus banCorpus = .valid ∧ validateCorpus banCorpus = .ok paths := by cbv
theorem grantor_only_misses_ancestor : oldTerminationGuard banCorpus "B" = true ∧ prTermination banCorpus "B" = false := by cbv
theorem ancestor_termination_ends_ban : prohibitionActive banCorpus paths ban 10 = true ∧
    prohibitionActive (terminate banCorpus "B") paths ban 10 = false := by cbv
theorem parallel_path_survives : pathActive banCorpus fallbackPath 10 = true ∧
    pathActive (terminate banCorpus "B") fallbackPath 10 = true := by cbv
theorem anchored_permission_ends : pathActive banCorpus mainPath 10 = true ∧
    pathActive (terminate banCorpus "B") mainPath 10 = false := by cbv

/-- Synthetic typed state, not a witnessed signed replay prefix. The uncapped
    format-2 ledger is distinct from the corpus's capped usage table. -/
def before : State := {
  corpus := base
  head := {hash := "head",position := 6,canonicalTime := 10}
  format2Usage := [{authorityId := "a-main",admittedTransactionCount := 1, admittedCumulativeAmount := 115792089237316195423570985008687907853269984665640564039457584007913129639935}] }
def after : State := {before with corpus := terminate before.corpus "B"}
def req : Request := {actorId := "A",action := "read",resource := "r",claimedAt := 10,amount := some 1}
def input : Input := {expectedHead := before.head,domain := before.domain,request := req,evaluationTime := 10}
def result (s : State) : Decision := authorizeState s input
def allows : Decision → Bool | .allow _ => true | _ => false

theorem residual_corpus_valid : corpusStatus base = .valid ∧ validateCorpus base = .ok paths := by cbv
theorem residual_exact_guard : prTermination before.corpus "B" = true := by cbv
theorem residual_zero_prohibitions : before.corpus.prohibitions = [] ∧ after.corpus.prohibitions = [] := by cbv
theorem amount_limit_value : maxAmount = 115792089237316195423570985008687907853269984665640564039457584007913129639935 := by decide
theorem time_limit_value : maxU53 = 9007199254740991 := by decide
/-- Superseded by A-135.3: this retained corpus now allows before and after. -/
theorem superseded_residual_amount_before : allows (result before) = true := by
  simp only [result,authorizeState,stageAfterCorpus,evaluateAlgebra,evaluateCandidate,failureSets,requestProblem,amount_limit_value,time_limit_value]
  cbv
theorem superseded_residual_amount_after : allows (result after) = true := by
  simp only [result,authorizeState,stageAfterCorpus,evaluateAlgebra,evaluateCandidate,failureSets,requestProblem,amount_limit_value,time_limit_value]
  cbv
theorem residual_actor_survives : inactive before.corpus req.actorId = false ∧ inactive after.corpus req.actorId = false := by cbv

/-- The old result_nonexpansion_false counterexample is superseded by A-135.3;
    ALLOW/ALLOW under r5.1. This finite witness is not a final-verdict theorem. -/
theorem superseded_result_counterexample_now_allows_both :
    allows (result before) = true ∧ allows (result after) = true :=
  ⟨superseded_residual_amount_before, superseded_residual_amount_after⟩

#print axioms ancestor_witness_valid
#print axioms grantor_only_misses_ancestor
#print axioms ancestor_termination_ends_ban
#print axioms parallel_path_survives
#print axioms anchored_permission_ends
#print axioms residual_corpus_valid
#print axioms residual_exact_guard
#print axioms residual_zero_prohibitions
#print axioms amount_limit_value
#print axioms time_limit_value
#print axioms superseded_residual_amount_before
#print axioms superseded_residual_amount_after
#print axioms residual_actor_survives
#print axioms superseded_result_counterexample_now_allows_both
end Authority.G64.Witnesses
