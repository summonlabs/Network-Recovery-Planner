// Network Recovery Planner - fabric definition, state and plan request.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#ifndef NRP_DOMAIN_HPP
#define NRP_DOMAIN_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "nrp/canonical.hpp"
#include "nrp/ids.hpp"
#include "nrp/model.hpp"

namespace nrp {

/// Hard bounds on every externally supplied collection. Nothing is materialised
/// before its declared size has been checked against these.
struct ModelLimits {
  std::uint32_t max_nodes = 4096;
  std::uint32_t max_links = 8192;
  std::uint32_t max_services = 1024;
  std::uint32_t max_resources = 1024;
  std::uint32_t max_actions = 512;
  std::uint32_t max_goals = 1024;
  std::uint32_t max_exclusion_groups = 512;
  std::uint32_t max_preconditions_per_action = 32;
  std::uint32_t max_effects_per_action = 32;
  std::uint32_t max_evidence_facts = 65536;
  std::uint32_t max_authority_bindings = 32;
  std::uint32_t max_fences = 1024;
  std::uint32_t max_action_occurrences = 16;
  std::uint32_t max_hold_steps = 64;
  std::uint32_t max_service_endpoints = 1000000;
  std::uint32_t max_string_length = 128;
};

const ModelLimits& default_model_limits() noexcept;

// ---------------------------------------------------------------------------
// Static definition
// ---------------------------------------------------------------------------

struct NodeSpec {
  NodeId id{};
  bool protected_node = false;
  friend bool operator<(const NodeSpec& a, const NodeSpec& b) { return a.id < b.id; }
  friend bool operator==(const NodeSpec& a, const NodeSpec& b) {
    return a.id == b.id && a.protected_node == b.protected_node;
  }
};

struct LinkSpec {
  LinkId id{};
  NodeId endpoint_a{};
  NodeId endpoint_b{};
  friend bool operator<(const LinkSpec& a, const LinkSpec& b) { return a.id < b.id; }
  friend bool operator==(const LinkSpec& a, const LinkSpec& b) {
    return a.id == b.id && a.endpoint_a == b.endpoint_a && a.endpoint_b == b.endpoint_b;
  }
};

struct ServiceSpec {
  ServiceId id{};
  /// Hard floor: no admissible plan step may drive reachability below this.
  std::uint32_t required_reachable = 0;
  /// Soft objective target used for recovery completeness.
  std::uint32_t target_reachable = 0;
  /// Structural maximum reachable endpoint count for the service.
  std::uint32_t max_reachable = 0;
  bool protected_service = false;
  friend bool operator<(const ServiceSpec& a, const ServiceSpec& b) { return a.id < b.id; }
  friend bool operator==(const ServiceSpec& a, const ServiceSpec& b) {
    return a.id == b.id && a.required_reachable == b.required_reachable &&
           a.target_reachable == b.target_reachable && a.max_reachable == b.max_reachable &&
           a.protected_service == b.protected_service;
  }
};

enum class ResourceKind : std::uint8_t {
  /// Units are consumed permanently; the sum over the whole plan is bounded.
  CONSUMABLE = 0,
  /// Units are held for hold_steps plan steps; overlap in any step is bounded.
  REUSABLE = 1,
  COUNT = 2,
};

const char* to_string(ResourceKind kind) noexcept;
bool is_valid(ResourceKind kind) noexcept;

struct ResourceSpec {
  ResourceId id{};
  ResourceKind kind = ResourceKind::CONSUMABLE;
  std::uint32_t capacity = 0;
  std::uint32_t hold_steps = 0;
  friend bool operator<(const ResourceSpec& a, const ResourceSpec& b) { return a.id < b.id; }
  friend bool operator==(const ResourceSpec& a, const ResourceSpec& b) {
    return a.id == b.id && a.kind == b.kind && a.capacity == b.capacity &&
           a.hold_steps == b.hold_steps;
  }
};

enum class PreconditionKind : std::uint8_t {
  LINK_OPERATIONAL = 0,
  LINK_NOT_OPERATIONAL = 1,
  NODE_OPERATIONAL = 2,
  NODE_NOT_OPERATIONAL = 3,
  SERVICE_REACHABLE_AT_LEAST = 4,
  SERVICE_REACHABLE_AT_MOST = 5,
  RESOURCE_AVAILABLE_AT_LEAST = 6,
  ACTION_EXECUTED_AT_LEAST = 7,
  COUNT = 8,
};

const char* to_string(PreconditionKind kind) noexcept;
bool is_valid(PreconditionKind kind) noexcept;
SubjectKind expected_subject(PreconditionKind kind) noexcept;

struct Precondition {
  PreconditionKind kind = PreconditionKind::LINK_OPERATIONAL;
  Subject subject{};
  std::uint64_t value = 0;
  friend bool operator==(const Precondition& a, const Precondition& b) {
    return a.kind == b.kind && a.subject == b.subject && a.value == b.value;
  }
  friend bool operator<(const Precondition& a, const Precondition& b) {
    if (a.subject != b.subject) return a.subject < b.subject;
    if (a.kind != b.kind) return static_cast<std::uint8_t>(a.kind) < static_cast<std::uint8_t>(b.kind);
    return a.value < b.value;
  }
};

enum class EffectKind : std::uint8_t {
  SET_LINK_OPERATIONAL = 0,
  SET_NODE_OPERATIONAL = 1,
  SERVICE_REACHABLE_DELTA = 2,
  MARK_RESOURCE_RESTORED = 3,
  /// Absolute service reachability. Unlike a delta this resolves an UNKNOWN
  /// reachability into an established value.
  SET_SERVICE_REACHABLE = 4,
  /// Absolute remaining consumable units; also resolves UNKNOWN availability.
  SET_RESOURCE_AVAILABLE = 5,
  COUNT = 6,
};

const char* to_string(EffectKind kind) noexcept;
bool is_valid(EffectKind kind) noexcept;
SubjectKind expected_subject(EffectKind kind) noexcept;

struct Effect {
  EffectKind kind = EffectKind::SET_LINK_OPERATIONAL;
  Subject subject{};
  /// 0/1 for the operational SET_* effects, signed endpoint delta for
  /// SERVICE_REACHABLE_DELTA, absolute count for SET_SERVICE_REACHABLE and
  /// SET_RESOURCE_AVAILABLE, and 1 for MARK_RESOURCE_RESTORED.
  std::int64_t value = 0;
  friend bool operator==(const Effect& a, const Effect& b) {
    return a.kind == b.kind && a.subject == b.subject && a.value == b.value;
  }
  friend bool operator<(const Effect& a, const Effect& b) {
    if (a.subject != b.subject) return a.subject < b.subject;
    if (a.kind != b.kind) return static_cast<std::uint8_t>(a.kind) < static_cast<std::uint8_t>(b.kind);
    return a.value < b.value;
  }
};

struct ResourceUse {
  ResourceId resource{};
  std::uint32_t units = 0;
  friend bool operator==(const ResourceUse& a, const ResourceUse& b) {
    return a.resource == b.resource && a.units == b.units;
  }
  friend bool operator<(const ResourceUse& a, const ResourceUse& b) {
    if (a.resource != b.resource) return a.resource < b.resource;
    return a.units < b.units;
  }
};

enum class ActionKind : std::uint8_t {
  REROUTE = 0,
  REPLACE = 1,
  RESTART = 2,
  DRAIN = 3,
  ISOLATE = 4,
  RESTORE = 5,
  DEGRADE = 6,
  COUNT = 7,
};

const char* to_string(ActionKind kind) noexcept;
bool is_valid(ActionKind kind) noexcept;

enum class Reversibility : std::uint8_t {
  REVERSIBLE = 0,
  IRREVERSIBLE = 1,
  COUNT = 2,
};

const char* to_string(Reversibility value) noexcept;
bool is_valid(Reversibility value) noexcept;

/// Declares that the min_occurrences-th execution of predecessor must already
/// have happened before the dependent action executes. Occurrence counts make
/// explicit iterative phases modelable while keeping the state space finite.
struct ActionDependency {
  ActionId predecessor{};
  std::uint32_t min_occurrences = 1;
  friend bool operator==(const ActionDependency& a, const ActionDependency& b) {
    return a.predecessor == b.predecessor && a.min_occurrences == b.min_occurrences;
  }
  friend bool operator<(const ActionDependency& a, const ActionDependency& b) {
    if (a.predecessor != b.predecessor) return a.predecessor < b.predecessor;
    return a.min_occurrences < b.min_occurrences;
  }
};

struct ActionSpec {
  ActionId id{};
  std::string name;
  ActionKind kind = ActionKind::RESTORE;
  Reversibility reversibility = Reversibility::IRREVERSIBLE;
  /// Action that compensates this one. Required exactly when REVERSIBLE.
  ActionId compensation{};
  std::uint32_t blast_radius = 0;
  std::uint32_t disruption = 0;
  std::uint64_t cost_units = 0;
  std::uint64_t duration_ticks = 0;
  std::uint32_t max_occurrences = 1;
  AuthorityDomain required_domain = AuthorityDomain::RECOVERY_ADMISSION;
  AuthorityLevel required_level = AuthorityLevel::AUTHORIZATION;
  std::vector<Precondition> preconditions;
  std::vector<Effect> effects;
  std::vector<ResourceUse> resource_uses;
  /// Dependencies of this action ("requires" is a C++20 keyword, hence the name).
  std::vector<ActionDependency> dependencies;
  std::vector<ExclusionGroupId> exclusion_groups;
};

enum class GoalKind : std::uint8_t {
  SERVICE_REACHABLE_AT_LEAST = 0,
  LINK_OPERATIONAL = 1,
  NODE_OPERATIONAL = 2,
  RESOURCE_RESTORED = 3,
  COUNT = 4,
};

const char* to_string(GoalKind kind) noexcept;
bool is_valid(GoalKind kind) noexcept;
SubjectKind expected_subject(GoalKind kind) noexcept;

struct GoalSpec {
  GoalKind kind = GoalKind::LINK_OPERATIONAL;
  Subject subject{};
  std::uint64_t value = 0;
  std::uint32_t weight = 1;
  friend bool operator==(const GoalSpec& a, const GoalSpec& b) {
    return a.kind == b.kind && a.subject == b.subject && a.value == b.value && a.weight == b.weight;
  }
};

struct ExclusionGroup {
  ExclusionGroupId id{};
  std::uint32_t max_selected = 1;
  friend bool operator<(const ExclusionGroup& a, const ExclusionGroup& b) { return a.id < b.id; }
  friend bool operator==(const ExclusionGroup& a, const ExclusionGroup& b) {
    return a.id == b.id && a.max_selected == b.max_selected;
  }
};

/// Durable, static problem definition. Canonically ordered after canonicalise().
struct FabricDefinition {
  std::vector<NodeSpec> nodes;
  std::vector<LinkSpec> links;
  std::vector<ServiceSpec> services;
  std::vector<ResourceSpec> resources;
  std::vector<ActionSpec> actions;
  std::vector<GoalSpec> goals;
  std::vector<ExclusionGroup> exclusion_groups;

  void canonicalise();
  Digest digest() const;
  void encode(CanonicalWriter& writer) const;

  const ActionSpec* find_action(ActionId id) const noexcept;
  const ResourceSpec* find_resource(ResourceId id) const noexcept;
  const ServiceSpec* find_service(ServiceId id) const noexcept;
  std::size_t action_index(ActionId id) const noexcept;
  std::size_t resource_index(ResourceId id) const noexcept;
  std::size_t service_index(ServiceId id) const noexcept;
  std::size_t node_index(NodeId id) const noexcept;
  std::size_t link_index(LinkId id) const noexcept;
};

/// Structural validation of a definition. Returns the first violation with a
/// reason code; a definition that fails here is never planned against.
Status validate_definition(const FabricDefinition& definition,
                           const ModelLimits& limits,
                           ExplanationLog* log);

// ---------------------------------------------------------------------------
// Dynamic state
// ---------------------------------------------------------------------------

/// State of the fabric model during planning. All vectors are parallel to the
/// canonically ordered definition vectors.
struct FabricState {
  std::vector<std::uint8_t> node_operational;
  std::vector<std::uint8_t> link_operational;
  std::vector<std::uint8_t> resource_restored;
  /// Remaining consumable units (capacity minus consumed) for CONSUMABLE
  /// resources; equal to capacity for REUSABLE resources.
  std::vector<std::uint32_t> resource_available;
  std::vector<std::uint32_t> service_reachable;
  std::vector<std::uint32_t> action_occurrences;
  /// Establishment masks. 0 means the value is UNKNOWN, never "false": an
  /// unknown value never satisfies a precondition and never proves a goal.
  std::vector<std::uint8_t> node_known;
  std::vector<std::uint8_t> link_known;
  std::vector<std::uint8_t> resource_known;
  std::vector<std::uint8_t> service_known;
  std::uint64_t tick = 0;

  void encode(CanonicalWriter& writer) const;
};

/// Active hold of a REUSABLE resource. Kept sorted by (resource index,
/// remaining steps, units) so state comparison is order independent.
struct ResourceHold {
  std::uint32_t resource_index = 0;
  std::uint32_t units = 0;
  std::uint32_t remaining_steps = 0;
  friend bool operator==(const ResourceHold& a, const ResourceHold& b) {
    return a.resource_index == b.resource_index && a.units == b.units &&
           a.remaining_steps == b.remaining_steps;
  }
  friend bool operator<(const ResourceHold& a, const ResourceHold& b) {
    if (a.resource_index != b.resource_index) return a.resource_index < b.resource_index;
    if (a.remaining_steps != b.remaining_steps) return a.remaining_steps < b.remaining_steps;
    return a.units < b.units;
  }
};

using HoldProfile = std::vector<ResourceHold>;

// ---------------------------------------------------------------------------
// Policy and request
// ---------------------------------------------------------------------------

/// Bounded search and admissibility policy. The policy digest is recorded in
/// every proof so the exact assumption set of a proof is auditable.
struct PlanPolicy {
  bool allow_irreversible_actions = false;
  bool require_current_authority = true;
  std::uint64_t max_plan_steps = 32;
  std::uint64_t max_nodes_expanded = 200000;
  std::uint64_t max_generated_states = 400000;
  std::uint64_t max_frontier_entries = 200000;
  std::uint32_t budget_scale = 1;

  Digest digest() const;
  void encode(CanonicalWriter& writer) const;
};

struct PlanRequest {
  RequestId id{};
  Epoch coordinator_epoch{};
  BootId boot{};
  AttemptId attempt{};
  FabricDefinition definition;
  EvidenceBundle evidence;
  AuthorityVector authority;
  PlanPolicy policy;
  std::vector<Fence> fences;

  Digest digest() const;
  void encode(CanonicalWriter& writer) const;
};

/// Total decoder for a canonical plan request. Rejects: trailing bytes, declared
/// sizes above the model limits, invalid enums, and referential violations.
Result<PlanRequest> decode_plan_request(const std::vector<std::uint8_t>& bytes,
                                        const ModelLimits& limits);

}  // namespace nrp

#endif  // NRP_DOMAIN_HPP
