// Network Recovery Planner - deterministic lexicographic objective.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#ifndef NRP_OBJECTIVE_HPP
#define NRP_OBJECTIVE_HPP

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "nrp/canonical.hpp"
#include "nrp/ids.hpp"

namespace nrp {

/// Number of numeric objective components. The final tie-break (canonical action
/// encoding) is compared separately and is not a numeric component.
inline constexpr std::size_t kObjectiveComponents = 8;

/// Deterministic total objective, ordered lexicographically:
///
///   0 safety_violations          protected-service requirement breaches during
///                                the plan. Must be zero (hard constraint).
///   1 service_preservation_gap   worst-case protected service shortfall.
///                                Must be zero (hard constraint).
///   2 recovery_incompleteness    soft gap against service targets plus the
///                                weight of unmet goals (goals are hard: a plan
///                                with unmet goals is not a solution at all).
///   3 blast_radius               sum of per-action blast radius.
///   4 action_count               number of executed steps.
///   5 disruption                 sum of per-action disruption weight.
///   6 cost_units                 sum of per-action estimated cost.
///   7 duration_ticks             sum of per-action estimated duration.
///
/// Ties are broken by the canonical action encoding compared lexicographically
/// as a vector of action identities, which is unique per plan.
struct ObjectiveVector {
  std::array<std::uint64_t, kObjectiveComponents> component{};

  std::uint64_t& operator[](std::size_t index) { return component[index]; }
  std::uint64_t operator[](std::size_t index) const { return component[index]; }

  /// Component-wise saturating addition with explicit overflow detection.
  static bool add(const ObjectiveVector& a, const ObjectiveVector& b, ObjectiveVector* out) noexcept;

  bool is_safety_clean() const noexcept { return component[0] == 0 && component[1] == 0; }

  std::string to_string() const;
  void encode(CanonicalWriter& writer) const;
};

/// Comparator over (objective, canonical encoding). Total and deterministic.
struct ScoredPlanLess {
  bool operator()(const ObjectiveVector& a_obj,
                  const std::vector<ActionId>& a_enc,
                  const ObjectiveVector& b_obj,
                  const std::vector<ActionId>& b_enc) const noexcept;
};

int compare_objective(const ObjectiveVector& a, const ObjectiveVector& b) noexcept;
int compare_encoding(const std::vector<ActionId>& a, const std::vector<ActionId>& b) noexcept;

const char* objective_component_name(std::size_t index) noexcept;

}  // namespace nrp

#endif  // NRP_OBJECTIVE_HPP
