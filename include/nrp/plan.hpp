// Network Recovery Planner - plans, decisions and proof certificates.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#ifndef NRP_PLAN_HPP
#define NRP_PLAN_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "nrp/canonical.hpp"
#include "nrp/domain.hpp"
#include "nrp/model.hpp"
#include "nrp/objective.hpp"

namespace nrp {

/// Every externally visible planning outcome. UNKNOWN/STALE/CONFLICT/INVALID/
/// UNSUPPORTED and bounded-search outcomes are first class and are never folded
/// into PLAN_FOUND or into PROVEN_INFEASIBLE.
enum class PlanDecision : std::uint8_t {
  PLAN_FOUND = 0,
  PROVEN_INFEASIBLE = 1,
  INDETERMINATE_SEARCH_LIMIT = 2,
  INDETERMINATE_INCOMPLETE_EVIDENCE = 3,
  REJECTED_INVALID_REQUEST = 4,
  REJECTED_UNSUPPORTED_PROBLEM = 5,
  REJECTED_STALE_AUTHORITY = 6,
  REJECTED_UNKNOWN_AUTHORITY = 7,
  REJECTED_CONFLICTING_AUTHORITY = 8,
  REJECTED_FENCED = 9,
  REJECTED_EXHAUSTED = 10,
  COUNT = 11,
};

const char* to_string(PlanDecision decision) noexcept;
bool is_valid(PlanDecision decision) noexcept;
bool is_indeterminate(PlanDecision decision) noexcept;
bool is_rejection(PlanDecision decision) noexcept;

/// Evidence generation bound by a step. Recomputed independently by
/// validate_plan: a plan cannot widen or narrow its own evidence binding.
struct EvidenceBinding {
  EvidenceKind kind = EvidenceKind::LINK_OPERATIONAL;
  Subject subject{};
  Generation generation{};
  friend bool operator==(const EvidenceBinding& a, const EvidenceBinding& b) {
    return a.kind == b.kind && a.subject == b.subject && a.generation == b.generation;
  }
  friend bool operator<(const EvidenceBinding& a, const EvidenceBinding& b) {
    if (a.subject != b.subject) return a.subject < b.subject;
    if (a.kind != b.kind) return static_cast<std::uint8_t>(a.kind) < static_cast<std::uint8_t>(b.kind);
    return a.generation < b.generation;
  }
};

struct PlanStep {
  std::uint32_t index = 0;
  ActionId action{};
  /// 1-based occurrence number of this action inside the plan.
  std::uint32_t occurrence = 1;
  std::uint64_t start_tick = 0;
  std::uint64_t end_tick = 0;

  /// Authority this step requires from an adjacent runtime. The planner issues
  /// RECOMMENDATION only; it never asserts that the step is authorized.
  AuthorityDomain required_domain = AuthorityDomain::RECOVERY_ADMISSION;
  AuthorityLevel required_level = AuthorityLevel::AUTHORIZATION;
  Generation required_generation{};
  AuthorityLevel issued_level = AuthorityLevel::RECOMMENDATION;

  std::vector<EvidenceBinding> evidence;
  bool irreversible = true;
  /// Compensation action recorded for a reversible step; empty otherwise.
  ActionId compensation{};

  friend bool operator==(const PlanStep& a, const PlanStep& b);
};

struct RecoveryPlan {
  PlanId id{};
  RequestId request{};
  Epoch coordinator_epoch{};
  BootId boot{};
  AttemptId attempt{};
  std::vector<PlanStep> steps;
  ObjectiveVector objective{};

  Digest request_digest{};
  Digest definition_digest{};
  Digest evidence_digest{};
  Digest authority_digest{};
  Digest policy_digest{};
  Digest plan_digest{};

  std::vector<Explanation> explanations;

  std::vector<ActionId> encoding() const;
  /// Recomputes plan_digest from the canonical encoding with the digest field
  /// zeroed. Used by both the planner and the independent validator.
  Digest compute_digest() const;
  void encode(CanonicalWriter& writer) const;
  std::string render() const;
};

/// Kind of a machine-checkable infeasibility proof. A proof of infeasibility is
/// only ever emitted when one of these certificates is valid for all
/// constraints of the request.
enum class ProofKind : std::uint8_t {
  EXHAUSTIVE_SEARCH = 0,
  DEPENDENCY_CYCLE = 1,
  GOAL_UPPER_BOUND = 2,
  COUNT = 3,
};

const char* to_string(ProofKind kind) noexcept;

struct InfeasibilityCertificate {
  ProofKind kind = ProofKind::EXHAUSTIVE_SEARCH;
  Digest request_digest{};
  Digest policy_digest{};
  /// Nodes expanded / generated during the exhaustive exploration.
  std::uint64_t nodes_expanded = 0;
  std::uint64_t nodes_generated = 0;
  std::uint64_t reachable_states = 0;
  /// Actions forming a dependency cycle, canonically ordered (DEPENDENCY_CYCLE).
  std::vector<ActionId> cycle;
  /// Subject whose goal was proven unreachable, with the derived bound.
  Subject unreachable_subject{};
  std::uint64_t unreachable_value = 0;
  std::uint64_t required_value = 0;
  /// Explicit assumption set of the proof. Never empty.
  std::vector<std::string> assumptions;
  std::vector<Explanation> explanations;
};

struct SearchStats {
  std::uint64_t nodes_expanded = 0;
  std::uint64_t nodes_generated = 0;
  std::uint64_t nodes_pruned_by_dominance = 0;
  std::uint64_t nodes_pruned_by_safety = 0;
  std::uint64_t nodes_pruned_by_authority = 0;
  std::uint64_t nodes_pruned_by_policy = 0;
  std::uint64_t frontier_high_water = 0;
  std::uint64_t states_revisited = 0;
  std::uint64_t budget_nodes = 0;
  bool budget_exhausted = false;
  bool frontier_emptied = false;
};

struct PlanningResult {
  PlanDecision decision = PlanDecision::REJECTED_INVALID_REQUEST;
  RequestId request{};
  Epoch coordinator_epoch{};
  BootId boot{};
  AttemptId attempt{};
  std::optional<RecoveryPlan> plan;
  std::optional<InfeasibilityCertificate> certificate;
  SearchStats stats{};
  /// Subjects whose evidence could not be established. Non-empty here means the
  /// result can never claim PROVEN_INFEASIBLE without weakening the claim.
  std::vector<Subject> unresolved_subjects;
  std::vector<Explanation> explanations;
  Digest request_digest{};

  std::string render() const;
};

}  // namespace nrp

#endif  // NRP_PLAN_HPP
