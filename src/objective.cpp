// Network Recovery Planner - objective vector and plan encoding.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "nrp/objective.hpp"

#include <sstream>

namespace nrp {

const char* objective_component_name(std::size_t index) noexcept {
  switch (index) {
    case 0: return "safety_violations";
    case 1: return "service_preservation_gap";
    case 2: return "recovery_incompleteness";
    case 3: return "blast_radius";
    case 4: return "action_count";
    case 5: return "disruption";
    case 6: return "cost_units";
    case 7: return "duration_ticks";
    default: return "unknown";
  }
}

bool ObjectiveVector::add(const ObjectiveVector& a, const ObjectiveVector& b, ObjectiveVector* out) noexcept {
  ObjectiveVector result;
  for (std::size_t index = 0; index < kObjectiveComponents; ++index) {
    std::uint64_t sum = 0;
    if (add_overflow(a.component[index], b.component[index], &sum)) return false;
    result.component[index] = sum;
  }
  *out = result;
  return true;
}

std::string ObjectiveVector::to_string() const {
  std::ostringstream out;
  out << '[';
  for (std::size_t index = 0; index < kObjectiveComponents; ++index) {
    if (index != 0) out << ' ';
    out << component[index];
  }
  out << ']';
  return out.str();
}

void ObjectiveVector::encode(CanonicalWriter& writer) const {
  for (std::size_t index = 0; index < kObjectiveComponents; ++index) {
    writer.u64(component[index]);
  }
}

int compare_objective(const ObjectiveVector& a, const ObjectiveVector& b) noexcept {
  for (std::size_t index = 0; index < kObjectiveComponents; ++index) {
    if (a.component[index] < b.component[index]) return -1;
    if (a.component[index] > b.component[index]) return 1;
  }
  return 0;
}

int compare_encoding(const std::vector<ActionId>& a, const std::vector<ActionId>& b) noexcept {
  const std::size_t common = a.size() < b.size() ? a.size() : b.size();
  for (std::size_t index = 0; index < common; ++index) {
    if (a[index] < b[index]) return -1;
    if (a[index] > b[index]) return 1;
  }
  if (a.size() < b.size()) return -1;
  if (a.size() > b.size()) return 1;
  return 0;
}

bool ScoredPlanLess::operator()(const ObjectiveVector& a_obj,
                                const std::vector<ActionId>& a_enc,
                                const ObjectiveVector& b_obj,
                                const std::vector<ActionId>& b_enc) const noexcept {
  const int objective_order = compare_objective(a_obj, b_obj);
  if (objective_order != 0) return objective_order < 0;
  return compare_encoding(a_enc, b_enc) < 0;
}

}  // namespace nrp
