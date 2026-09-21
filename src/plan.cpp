// Network Recovery Planner - plans, decisions and proofs.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "nrp/plan.hpp"

#include "nrp/codec.hpp"

#include <sstream>

namespace nrp {

const char* to_string(PlanDecision decision) noexcept {
  switch (decision) {
    case PlanDecision::PLAN_FOUND: return "PLAN_FOUND";
    case PlanDecision::PROVEN_INFEASIBLE: return "PROVEN_INFEASIBLE";
    case PlanDecision::INDETERMINATE_SEARCH_LIMIT: return "INDETERMINATE_SEARCH_LIMIT";
    case PlanDecision::INDETERMINATE_INCOMPLETE_EVIDENCE: return "INDETERMINATE_INCOMPLETE_EVIDENCE";
    case PlanDecision::REJECTED_INVALID_REQUEST: return "REJECTED_INVALID_REQUEST";
    case PlanDecision::REJECTED_UNSUPPORTED_PROBLEM: return "REJECTED_UNSUPPORTED_PROBLEM";
    case PlanDecision::REJECTED_STALE_AUTHORITY: return "REJECTED_STALE_AUTHORITY";
    case PlanDecision::REJECTED_UNKNOWN_AUTHORITY: return "REJECTED_UNKNOWN_AUTHORITY";
    case PlanDecision::REJECTED_CONFLICTING_AUTHORITY: return "REJECTED_CONFLICTING_AUTHORITY";
    case PlanDecision::REJECTED_FENCED: return "REJECTED_FENCED";
    case PlanDecision::REJECTED_EXHAUSTED: return "REJECTED_EXHAUSTED";
    case PlanDecision::COUNT: return "COUNT";
  }
  return "UNRECOGNISED_PLAN_DECISION";
}

bool is_valid(PlanDecision decision) noexcept {
  switch (decision) {
    case PlanDecision::PLAN_FOUND:
    case PlanDecision::PROVEN_INFEASIBLE:
    case PlanDecision::INDETERMINATE_SEARCH_LIMIT:
    case PlanDecision::INDETERMINATE_INCOMPLETE_EVIDENCE:
    case PlanDecision::REJECTED_INVALID_REQUEST:
    case PlanDecision::REJECTED_UNSUPPORTED_PROBLEM:
    case PlanDecision::REJECTED_STALE_AUTHORITY:
    case PlanDecision::REJECTED_UNKNOWN_AUTHORITY:
    case PlanDecision::REJECTED_CONFLICTING_AUTHORITY:
    case PlanDecision::REJECTED_FENCED:
    case PlanDecision::REJECTED_EXHAUSTED:
      return true;
    case PlanDecision::COUNT:
      return false;
  }
  return false;
}

bool is_indeterminate(PlanDecision decision) noexcept {
  return decision == PlanDecision::INDETERMINATE_SEARCH_LIMIT ||
         decision == PlanDecision::INDETERMINATE_INCOMPLETE_EVIDENCE ||
         decision == PlanDecision::REJECTED_EXHAUSTED;
}

bool is_rejection(PlanDecision decision) noexcept {
  switch (decision) {
    case PlanDecision::REJECTED_INVALID_REQUEST:
    case PlanDecision::REJECTED_UNSUPPORTED_PROBLEM:
    case PlanDecision::REJECTED_STALE_AUTHORITY:
    case PlanDecision::REJECTED_UNKNOWN_AUTHORITY:
    case PlanDecision::REJECTED_CONFLICTING_AUTHORITY:
    case PlanDecision::REJECTED_FENCED:
    case PlanDecision::REJECTED_EXHAUSTED:
      return true;
    default:
      return false;
  }
}

bool operator==(const PlanStep& a, const PlanStep& b) {
  return a.index == b.index && a.action == b.action && a.occurrence == b.occurrence &&
         a.start_tick == b.start_tick && a.end_tick == b.end_tick &&
         a.required_domain == b.required_domain && a.required_level == b.required_level &&
         a.required_generation == b.required_generation && a.issued_level == b.issued_level &&
         a.evidence == b.evidence && a.irreversible == b.irreversible &&
         a.compensation == b.compensation;
}

std::vector<ActionId> RecoveryPlan::encoding() const {
  std::vector<ActionId> out;
  out.reserve(steps.size());
  for (const PlanStep& step : steps) {
    out.push_back(step.action);
  }
  return out;
}

Digest RecoveryPlan::compute_digest() const {
  // The plan identity is derived from this digest, so the identity field is
  // zeroed while hashing: otherwise the digest would depend on itself.
  RecoveryPlan canonical = *this;
  canonical.id = PlanId{};
  canonical.plan_digest = Digest{};
  CanonicalWriter writer;
  encode_plan(canonical, writer);
  return digest_of(writer.buffer());
}

void RecoveryPlan::encode(CanonicalWriter& writer) const {
  encode_plan(*this, writer);
}

std::string RecoveryPlan::render() const {
  std::ostringstream out;
  out << "plan " << id.value() << " request " << request.value() << " epoch " << coordinator_epoch.value()
      << " boot " << boot.value() << " attempt " << attempt.value() << "\n";
  out << "  objective " << objective.to_string() << " digest " << plan_digest.hex() << "\n";
  for (const PlanStep& step : steps) {
    out << "  step " << step.index << " action " << step.action.value() << " occurrence "
        << step.occurrence << " ticks [" << step.start_tick << ',' << step.end_tick << ')'
        << " requires " << to_string(step.required_domain) << "/" << to_string(step.required_level)
        << "@" << step.required_generation.value << " issued " << to_string(step.issued_level);
    if (step.irreversible) out << " IRREVERSIBLE";
    else out << " compensable-by " << step.compensation.value();
    out << "\n";
  }
  return out.str();
}

const char* to_string(ProofKind kind) noexcept {
  switch (kind) {
    case ProofKind::EXHAUSTIVE_SEARCH: return "EXHAUSTIVE_SEARCH";
    case ProofKind::DEPENDENCY_CYCLE: return "DEPENDENCY_CYCLE";
    case ProofKind::GOAL_UPPER_BOUND: return "GOAL_UPPER_BOUND";
    case ProofKind::COUNT: return "COUNT";
  }
  return "UNRECOGNISED_PROOF_KIND";
}

std::string PlanningResult::render() const {
  std::ostringstream out;
  out << "decision " << to_string(decision) << " request " << request.value() << " epoch "
      << coordinator_epoch.value() << " boot " << boot.value() << "\n";
  out << "  nodes expanded " << stats.nodes_expanded << " generated " << stats.nodes_generated
      << " budget " << stats.budget_nodes << " budget_exhausted "
      << (stats.budget_exhausted ? "true" : "false") << " frontier_empty "
      << (stats.frontier_emptied ? "true" : "false") << "\n";
  if (plan.has_value()) out << plan->render();
  if (certificate.has_value()) {
    out << "  proof " << to_string(certificate->kind) << " expanded "
        << certificate->nodes_expanded << " generated " << certificate->nodes_generated << "\n";
    for (const std::string& assumption : certificate->assumptions) {
      out << "    assumption: " << assumption << "\n";
    }
  }
  if (!unresolved_subjects.empty()) {
    out << "  unresolved subjects:";
    for (const Subject& subject : unresolved_subjects) out << ' ' << describe(subject);
    out << "\n";
  }
  for (const Explanation& explanation : explanations) {
    out << "  " << to_string(explanation.code);
    if (!explanation.text.empty()) out << ": " << explanation.text;
    out << "\n";
  }
  return out.str();
}

}  // namespace nrp
