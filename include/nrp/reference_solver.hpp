// Network Recovery Planner - slow independent exact reference solver.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#ifndef NRP_REFERENCE_SOLVER_HPP
#define NRP_REFERENCE_SOLVER_HPP

#include <cstdint>
#include <vector>

#include "nrp/domain.hpp"
#include "nrp/objective.hpp"

namespace nrp {

struct ReferenceLimits {
  /// Hard bound on enumerated sequences. Reaching it is reported, never hidden.
  std::uint64_t max_sequences = 40000000;
  std::uint64_t max_plan_steps = 8;
};

/// Result of the exhaustive reference enumeration.
///
/// The reference solver enumerates *every* action sequence within the limits,
/// simulates each one from the initial state with a from-scratch checker, and
/// keeps the lexicographic minimum over (objective, canonical encoding). It
/// shares no pruning, no dominance rule and no simulation code with the
/// production planner, which is what makes it usable as a differential oracle.
struct ReferenceOutcome {
  enum class Kind : std::uint8_t {
    COMPLETED = 0,      // full enumeration finished: the answer is exact
    LIMIT_REACHED = 1,  // enumeration aborted by a reference bound: not an answer
    INVALID_INPUT = 2,  // request structurally invalid
  };

  Kind kind = Kind::INVALID_INPUT;
  bool plan_found = false;
  ObjectiveVector objective{};
  std::vector<ActionId> encoding;
  std::uint64_t sequences_examined = 0;
  std::uint64_t valid_plans = 0;
};

ReferenceOutcome reference_solve(const PlanRequest& request, const ReferenceLimits& limits);

/// Re-runs the reference checker on one explicit sequence. Returns true only if
/// the sequence is a valid recovery plan for the request.
bool reference_check_sequence(const PlanRequest& request,
                              const std::vector<ActionId>& encoding);

}  // namespace nrp

#endif  // NRP_REFERENCE_SOLVER_HPP
