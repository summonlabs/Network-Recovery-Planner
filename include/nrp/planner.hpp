// Network Recovery Planner - bounded deterministic plan search.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#ifndef NRP_PLANNER_HPP
#define NRP_PLANNER_HPP

#include "nrp/domain.hpp"
#include "nrp/plan.hpp"

namespace nrp {

/// Bounded best-first recovery planner.
///
/// Algorithm: uniform-cost (Dijkstra) exploration of the finite plan-prefix
/// state space, ordered by the lexicographic objective with the canonical action
/// encoding as final tie-break. Every action increment is a component-wise
/// non-negative vector, so lexicographic order is monotone under extension and
/// the first goal-satisfying state expanded is optimal. States are dominated by
/// the best (objective, encoding) with which they were reached.
///
/// Completeness: the state space is finite because every action has a bounded
/// occurrence count. If the frontier empties within budget, the absence of a
/// solution is a proof, not a heuristic failure. If the budget is reached first,
/// the result is INDETERMINATE_SEARCH_LIMIT and never PROVEN_INFEASIBLE.
class Planner {
 public:
  explicit Planner(ModelLimits limits = default_model_limits()) : limits_(limits) {}

  PlanningResult plan(const PlanRequest& request) const;

  const ModelLimits& limits() const noexcept { return limits_; }

 private:
  ModelLimits limits_;
};

/// Derives the initial fabric state from evidence, classifying every subject
/// that could not be established at the granted generation. Used by the planner;
/// validate.cpp contains an independent implementation on purpose.
struct DerivedState {
  FabricState state;
  /// Per subject: generation of the evidence fact the value came from.
  std::vector<std::pair<Subject, Generation>> generation_index;
  std::vector<Subject> unresolved;
  std::vector<Explanation> explanations;

  /// Generation bound for a subject, or a null Generation when unresolved.
  bool generation_of(const Subject& subject, Generation* out) const;
};

Status derive_initial_state(const FabricDefinition& definition,
                            const EvidenceBundle& evidence,
                            const AuthorityVector& authority,
                            const ModelLimits& limits,
                            DerivedState* out);

}  // namespace nrp

#endif  // NRP_PLANNER_HPP
