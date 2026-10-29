-- SelectLeanProofs: the 15 top theorems. For each: its type, then the axioms it depends on.
import AuthorityModel.Properties
import AuthorityModel.Completeness
import AuthorityModel.Bounds
import G65.Revocation
import OwnerPolicy.IronTrellis.Safety
import Committee.Threshold
import AccountingFamily.Faithful
import Anchor.Protocol
import Anchor.Chain

#check @Authority.authorizeState_soundness
#print axioms Authority.authorizeState_soundness
#check @Authority.authorizeState_every_required_partner
#print axioms Authority.authorizeState_every_required_partner
#check @Authority.selectGraph_fuel_sufficient
#print axioms Authority.selectGraph_fuel_sufficient
#check @Authority.G65.revocation_algebra_nonexpansion
#print axioms Authority.G65.revocation_algebra_nonexpansion
#check @Authority.G65.revised_allow_revocation_nonexpansion
#print axioms Authority.G65.revised_allow_revocation_nonexpansion
#check @IronTrellis.I06_distinct
#print axioms IronTrellis.I06_distinct
#check @IronTrellis.I07_quorum
#print axioms IronTrellis.I07_quorum
#check @IronTrellis.I18_attestation_binding
#print axioms IronTrellis.I18_attestation_binding
#check @Committee.human_requires_statement
#print axioms Committee.human_requires_statement
#check @Committee.committee_never_alone
#print axioms Committee.committee_never_alone
#check @Committee.committee_never_counts_rotation
#print axioms Committee.committee_never_counts_rotation
#check @Faithful.aggregate_with_revocations
#print axioms Faithful.aggregate_with_revocations
#check @Anchor.fork_refused
#print axioms Anchor.fork_refused
#check @Anchor.rollback_refused
#print axioms Anchor.rollback_refused
#check @Anchor.no_fork_after_run
#print axioms Anchor.no_fork_after_run
