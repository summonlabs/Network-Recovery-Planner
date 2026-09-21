// Network Recovery Planner - independent plan validation.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#ifndef NRP_VALIDATE_HPP
#define NRP_VALIDATE_HPP

#include <string>
#include <vector>

#include "nrp/domain.hpp"
#include "nrp/plan.hpp"

namespace nrp {

struct ValidationFinding {
  ReasonCode code = ReasonCode::NONE;
  /// Step index the finding applies to, or UINT32_MAX for plan level findings.
  std::uint32_t step_index = UINT32_MAX;
  Subject subject{};
  std::string text;
};

struct ValidationReport {
  bool valid = false;
  /// True when the objective recorded in the plan equals the objective
  /// recomputed by the validator.
  bool objective_matches = false;
  bool digest_matches = false;
  ObjectiveVector recomputed_objective{};
  Digest stated_plan_digest{};
  Digest recomputed_plan_digest{};
  std::vector<ValidationFinding> findings;

  std::string render() const;
};

/// Independently re-derives every precondition, ordering constraint, authority
/// binding, evidence binding, resource constraint, safety constraint and goal of
/// a plan from the request alone. The validator shares no simulation code with
/// the planner: it re-implements state evolution from scratch.
ValidationReport validate_plan(const PlanRequest& request, const RecoveryPlan& plan);

/// Validates an infeasibility certificate: proof kind, digest bindings, and the
/// proof content itself where it is independently checkable (dependency cycles
/// and goal upper bounds are re-derived from the definition).
ValidationReport validate_certificate(const PlanRequest& request,
                                      const InfeasibilityCertificate& certificate);

}  // namespace nrp

#endif  // NRP_VALIDATE_HPP
