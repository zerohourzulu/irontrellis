import OwnerPolicy.IronTrellis.Model
namespace IronTrellis.Examples
set_option maxRecDepth 20000
set_option maxHeartbeats 0

def key (n : Nat) : Key := ⟨n,n,true⟩
def statement (c expiry : Nat) : Attestation :=
  {subject := key c, attesterId := 101, audience := 1, notBefore := 0, expiresAt := expiry}
def strictPolicy (expiry : Nat) (checkpointThreshold : Nat := 1) : Policy :=
  {threshold := 2, byType := some [(.checkpoint, checkpointThreshold),(.budgetDeclare,1)],
   humanFloor := some true, attesters := some [key 101,key 102],
   attestations := some [statement 1 expiry, statement 2 expiry]}
def genesis (expiry : Nat := 10) (checkpointThreshold : Nat := 1) : Genesis :=
  {keys := [key 1,key 2], policy := some (strictPolicy expiry checkpointThreshold)}
def base : State := initialState (genesis 10 1)

def signedEvent (s : State) (t : Nat) (b : Body) (ks : List Key) : Event :=
  let e : Event := {id := s.position+1, time := t, body := b}
  let sigs := ks.map (fun k => Signature.mk k.id k.cred (challenge s e) true)
  {e with control := sigs.head?, additional := if sigs.length ≥ 2 then some sigs.tail else none}
def checkpoint (s : State) (t : Nat) (ks : List Key) : Event :=
  signedEvent s t {tag := .checkpoint} ks

theorem accepted_genesis : genesisValid (genesis 10 1) = true := by decide +kernel
theorem reachable_base : Reachable base := Reachable.genesis _ accepted_genesis

theorem L3_two_held_lapsed :
    meff base (checkpoint base 11 [key 1]) = 1 ∧
    cls base.epoch.p base.epoch.keys 11 1 = .lapsed ∧
    cls base.epoch.p base.epoch.keys 11 2 = .lapsed := by decide +kernel

theorem L3_single_rejected_T2 :
    verdict base (checkpoint base 11 [key 1]) = some .transitionInvalid := by decide +kernel

theorem L3_two_rejected_presence :
    verdict base (checkpoint base 11 [key 1,key 2]) = some .controlAuthorizationInvalid := by decide +kernel

theorem L3_control_at_horizon : Accepted base (checkpoint base 10 [key 1]) := by decide +kernel

theorem L3_control_threshold_two :
    Accepted (initialState (genesis 10 2))
      (checkpoint (initialState (genesis 10 2)) 11 [key 1,key 2]) := by decide +kernel

def maxBase : State := initialState (genesis MAXT 1)
theorem L12_max_genesis : genesisValid (genesis MAXT 1) = true := by decide +kernel
theorem L12_max_reachable : Reachable maxBase := Reachable.genesis _ L12_max_genesis

theorem L12_expiry_at_max :
    maxBase.time = 0 ∧ maxBase.epoch.p.horizon = MAXT ∧
    meff maxBase (checkpoint maxBase MAXT [key 1]) = 1 ∧
    cls maxBase.epoch.p maxBase.epoch.keys MAXT 1 = .lapsed := by decide +kernel

theorem L12_max_checkpoint_rejected :
    verdict maxBase (checkpoint maxBase MAXT [key 1]) = some .transitionInvalid := by decide +kernel

theorem L12_max_minus_one_accepted :
    Accepted maxBase (checkpoint maxBase (MAXT-1) [key 1]) := by decide +kernel

def renewedPolicy : Policy :=
  {strictPolicy 10 1 with attestations := some [{statement 1 20 with notBefore := 5, historyId := some 1},
     {statement 2 20 with notBefore := 5, historyId := some 1}]}
def restoration (s : State) : Event :=
  signedEvent s 5 {tag := .rotate, ownerKeys := [key 1,key 2], policy := some renewedPolicy} [key 1,key 2]

/- The .ordinary constructor represents PRINCIPAL_CREATED here; its detailed
   r4 principal fields are inherited through basePrecondition. The .session
   event maps to the separately reproduced connector REQUEST_REFUSED scaffold. -/
def principalEvent : Event := signedEvent base 0 {tag := .ordinary,target := 1} [key 1,key 2]
def withPrincipal : State := apply base principalEvent
def agentEvent : Event := signedEvent withPrincipal 1
  {tag := .agentDeclare, agent := {id := 7,epoch := 1}} [key 1,key 2]
def withAgent : State := apply withPrincipal agentEvent
def sessionEvent : Event := signedEvent withAgent 1
  {tag := .sessionAdmit, session := ⟨8,99,7,1,100⟩} [key 1,key 2]
def withSession : State := apply withAgent sessionEvent
def renewEvent : Event := restoration withSession
def afterRenewal : State := apply withSession renewEvent
def sessionAt10 : Event := {id := 6,time := 10,body := {tag := .session}}

theorem renewal_trace_principal : Accepted base principalEvent := by decide +kernel
theorem renewal_trace_agent : Accepted withPrincipal agentEvent := by decide +kernel
theorem renewal_trace_session_admission : Accepted withAgent sessionEvent := by decide +kernel
theorem renewal_trace_is_restoration : isRestoration withSession renewEvent = true := by decide +kernel
theorem renewal_trace_rotation : Accepted withSession renewEvent := by decide +kernel
theorem renewal_trace_session : Accepted afterRenewal sessionAt10 := by decide +kernel

theorem renewal_trace_reachable : Reachable (apply afterRenewal sessionAt10) :=
  Reachable.step (Reachable.step (Reachable.step (Reachable.step (Reachable.step reachable_base renewal_trace_principal) renewal_trace_agent)
    renewal_trace_session_admission) renewal_trace_rotation) renewal_trace_session

theorem L12_initial_expiry_necessity_refuted :
    base.epoch.p.horizon = 10 ∧ principalEvent.time < 10 ∧ agentEvent.time < 10 ∧ sessionEvent.time < 10 ∧ renewEvent.time < 10 ∧
    sessionAt10.time ≥ 10 ∧ sessionAt10.body.tag.control = false ∧
    Accepted afterRenewal sessionAt10 := by decide +kernel

theorem renewal_trace_without_renewal_rejects :
    verdict withSession sessionAt10 = some .transitionInvalid := by decide +kernel

theorem restoration_does_not_move_keys : afterRenewal.epoch.keys = base.epoch.keys := by decide +kernel

def lowerThresholdUnderLapse : Event :=
  signedEvent base 10 {tag := .rotate,ownerKeys := [key 1,key 2], policy := some {strictPolicy 10 1 with threshold := 1}} [key 1,key 2]
theorem restoration_cannot_lower_threshold :
    isRestoration base lowerThresholdUnderLapse = false ∧
    verdict base lowerThresholdUnderLapse = some .controlAuthorizationInvalid := by decide +kernel

def addCommitmentUnderLapse : Event :=
  signedEvent base 10 {tag := .rotate,ownerKeys := [key 1,key 2], policy := some {renewedPolicy with attestations := some [{statement 1 20 with notBefore := 10,historyId := some 1},
       {statement 2 20 with notBefore := 10,historyId := some 1}]}, digests := some [3]} [key 1,key 2]
theorem restoration_cannot_add_commitment :
    isRestoration base addCommitmentUnderLapse = false ∧
    verdict base addCommitmentUnderLapse = some .controlAuthorizationInvalid := by decide +kernel

def malformedPolicyEvent : Event :=
  {signedEvent base 1 {tag := .rotate,ownerKeys := [key 1,key 2],policy := some {threshold := 0}} [key 99] with capacityOK := false}
theorem shape_precedes_authorization :
    verdict base malformedPolicyEvent = some .eventDataInvalid := by decide +kernel

def badNextOnCheckpoint : Event :=
  {checkpoint base 1 [key 1] with next := (checkpoint base 1 [key 99]).control.map (fun s => [s])}
theorem closed_schema_rejects_next_on_checkpoint :
    verdict base badNextOnCheckpoint = some .eventDataInvalid := by decide +kernel

def recoveryPolicy : Policy :=
  {strictPolicy 10 1 with recovery := true, attestations := some [statement 1 10,statement 2 10,statement 3 10,statement 4 10]}
def recoveryGenesis : Genesis :=
  {keys := [key 1,key 2], digests := some [3,4], policy := some recoveryPolicy}
def recoveryBase : State := initialState recoveryGenesis
def recoverEvent : Event :=
  let b : Body := {tag := .rotate,ownerKeys := [key 3,key 4],digests := some [5,6], policy := some {strictPolicy 10 1 with attestations := some [statement 3 10,statement 4 10]}}
  let e := signedEvent recoveryBase 5 b [key 3,key 4]
  {e with next := some (signers e)}
theorem recovery_genesis_valid : genesisValid recoveryGenesis = true := by decide +kernel
theorem recovery_escrow_accepted : Accepted recoveryBase recoverEvent := by decide +kernel
theorem recovery_escrow_reachable : Reachable (apply recoveryBase recoverEvent) :=
  Reachable.step (Reachable.genesis _ recovery_genesis_valid) recovery_escrow_accepted
theorem recovery_escrow_structural : isRecovery recoveryBase recoverEvent = true := by decide +kernel

def loneEscrow : Event :=
  let e := signedEvent recoveryBase 5 recoverEvent.body [key 3]
  {e with next := recoverEvent.next}
theorem recovery_single_escrow_not_quorum :
    verdict recoveryBase loneEscrow = some .controlAuthorizationInvalid := by decide +kernel

def expiredEscrow : Event :=
  let e := signedEvent recoveryBase 10 recoverEvent.body [key 3,key 4]
  {e with next := some (signers e)}
theorem recovery_lapsed_escrow_rejected :
    isRecovery recoveryBase expiredEscrow = true ∧
    verdict recoveryBase expiredEscrow = some .controlAuthorizationInvalid := by decide +kernel

/- A kernel arithmetic refutation of the stronger interpretation of I42's
   renewal corollary: time headroom does not imply strict expiry headroom. -/
theorem I42_renewal_endpoint_obstruction :
    maxBase.time < MAXT ∧ ¬∃ expiry : Nat, MAXT < expiry ∧ expiry ≤ MAXT := by
  constructor
  · decide
  · omega

end IronTrellis.Examples
