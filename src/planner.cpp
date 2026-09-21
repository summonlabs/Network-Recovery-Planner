// Network Recovery Planner - bounded deterministic plan search.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// The planner is a uniform-cost (Dijkstra) exploration of the finite plan-prefix
// state space. Every step contributes a component-wise non-negative objective
// increment, so lexicographic order is monotone under extension and the first
// goal-satisfying node expanded is optimal. If the frontier empties inside the
// budget the absence of a plan is a proof; if the budget is reached first the
// answer is INDETERMINATE and never PROVEN_INFEASIBLE.
#include "nrp/planner.hpp"

#include <algorithm>
#include <deque>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace nrp {
namespace {

constexpr std::size_t kNpos = static_cast<std::size_t>(-1);
constexpr std::uint64_t kNoParent = ~static_cast<std::uint64_t>(0);

// ---------------------------------------------------------------------------
// Identity indexing
// ---------------------------------------------------------------------------

template <class Id>
std::size_t index_of(const Id& id, const std::vector<Id>& ids) {
  const auto it = std::lower_bound(ids.begin(), ids.end(), id);
  if (it == ids.end() || !(*it == id)) return kNpos;
  return static_cast<std::size_t>(it - ids.begin());
}

struct Indexer {
  const FabricDefinition* definition = nullptr;
  std::vector<NodeId> node_ids;
  std::vector<LinkId> link_ids;
  std::vector<ServiceId> service_ids;
  std::vector<ResourceId> resource_ids;
  std::vector<ActionId> action_ids;

  void build(const FabricDefinition& def) {
    definition = &def;
    node_ids.clear();
    link_ids.clear();
    service_ids.clear();
    resource_ids.clear();
    action_ids.clear();
    for (const NodeSpec& node : def.nodes) node_ids.push_back(node.id);
    for (const LinkSpec& link : def.links) link_ids.push_back(link.id);
    for (const ServiceSpec& service : def.services) service_ids.push_back(service.id);
    for (const ResourceSpec& resource : def.resources) resource_ids.push_back(resource.id);
    for (const ActionSpec& action : def.actions) action_ids.push_back(action.id);
  }

  std::size_t node(NodeId id) const { return index_of(id, node_ids); }
  std::size_t link(LinkId id) const { return index_of(id, link_ids); }
  std::size_t service(ServiceId id) const { return index_of(id, service_ids); }
  std::size_t resource(ResourceId id) const { return index_of(id, resource_ids); }
  std::size_t action(ActionId id) const { return index_of(id, action_ids); }

  std::size_t subject_index(const Subject& subject) const {
    switch (subject.kind) {
      case SubjectKind::NODE: return node(NodeId::from_value(subject.id));
      case SubjectKind::LINK: return link(LinkId::from_value(subject.id));
      case SubjectKind::SERVICE: return service(ServiceId::from_value(subject.id));
      case SubjectKind::RESOURCE: return resource(ResourceId::from_value(subject.id));
      case SubjectKind::ACTION: return action(ActionId::from_value(subject.id));
      case SubjectKind::NONE:
      case SubjectKind::FABRIC:
        return kNpos;
    }
    return kNpos;
  }
};

// ---------------------------------------------------------------------------
// Evidence reconciliation
// ---------------------------------------------------------------------------

struct SubjectResolution {
  Subject subject{};
  EvidenceKind kind = EvidenceKind::LINK_OPERATIONAL;
  SubjectState state = SubjectState::MISSING;
  std::uint64_t value = 0;
  Generation generation{};
  Sequence sequence{};
  std::uint32_t sources = 0;
};

int state_priority(SubjectState state) {
  switch (state) {
    case SubjectState::CONFLICT: return 6;
    case SubjectState::STALE: return 5;
    case SubjectState::AHEAD: return 4;
    case SubjectState::INVALID: return 3;
    case SubjectState::UNSUPPORTED: return 2;
    case SubjectState::MISSING: return 1;
    case SubjectState::RESOLVED: return 0;
    case SubjectState::COUNT: return 0;
  }
  return 0;
}

ReasonCode reason_for(SubjectState state) {
  switch (state) {
    case SubjectState::MISSING: return ReasonCode::EVIDENCE_SUBJECT_MISSING;
    case SubjectState::STALE: return ReasonCode::EVIDENCE_SUBJECT_STALE;
    case SubjectState::AHEAD: return ReasonCode::EVIDENCE_SUBJECT_AHEAD_OF_AUTHORITY;
    case SubjectState::CONFLICT: return ReasonCode::EVIDENCE_SUBJECT_CONFLICTING;
    case SubjectState::INVALID: return ReasonCode::EVIDENCE_SUBJECT_INVALID;
    case SubjectState::UNSUPPORTED: return ReasonCode::EVIDENCE_SUBJECT_UNSUPPORTED;
    case SubjectState::RESOLVED:
    case SubjectState::COUNT:
      return ReasonCode::NONE;
  }
  return ReasonCode::NONE;
}

AuthorityDomain domain_for_evidence(EvidenceKind kind) {
  switch (kind) {
    case EvidenceKind::LINK_OPERATIONAL:
    case EvidenceKind::NODE_OPERATIONAL:
    case EvidenceKind::SERVICE_REACHABLE_ENDPOINTS:
      return AuthorityDomain::FABRIC_STATE;
    case EvidenceKind::RESOURCE_AVAILABLE_UNITS:
    case EvidenceKind::RESOURCE_RESTORED:
      return AuthorityDomain::RESOURCE_LEASE;
    case EvidenceKind::COUNT:
      break;
  }
  return AuthorityDomain::FABRIC_STATE;
}

using ResolutionTable = std::map<EvidenceKey, SubjectResolution>;

class Reconciler {
 public:
  Reconciler(const FabricDefinition& definition,
             const Indexer& indexer,
             const AuthorityVector& authority,
             const ModelLimits& limits)
      : definition_(definition), indexer_(indexer), authority_(authority), limits_(limits) {}

  void ingest(const EvidenceFact& fact) {
    if (!is_valid(fact.kind)) return;
    auto entry = table_.find(EvidenceKey{fact.kind, fact.subject});
    if (entry == table_.end()) {
      SubjectResolution fresh;
      fresh.subject = fact.subject;
      fresh.kind = fact.kind;
      entry = table_.emplace(EvidenceKey{fact.kind, fact.subject}, fresh).first;
    }
    SubjectResolution& resolution = entry->second;
    if (fact.subject.kind != expected_subject(fact.kind) ||
        indexer_.subject_index(fact.subject) == kNpos ||
        fact.source_domain != domain_for_evidence(fact.kind) ||
        fact.label == TrustLabel::UNKNOWN || !value_in_domain(fact)) {
      downgrade(resolution, SubjectState::INVALID);
      return;
    }
    if (fact.label == TrustLabel::UNSUPPORTED) {
      downgrade(resolution, SubjectState::UNSUPPORTED);
      return;
    }
    const AuthorityBinding* binding = authority_.find(fact.source_domain);
    if (binding == nullptr) {
      downgrade(resolution, SubjectState::MISSING);
      return;
    }
    if (fact.generation < binding->granted) {
      downgrade(resolution, SubjectState::STALE);
      return;
    }
    if (fact.generation > binding->granted) {
      downgrade(resolution, SubjectState::AHEAD);
      return;
    }
    if (resolution.state == SubjectState::RESOLVED) {
      if (fact.sequence > resolution.sequence) {
        resolution.value = fact.value;
        resolution.generation = fact.generation;
        resolution.sequence = fact.sequence;
        resolution.sources = 1;
        return;
      }
      if (fact.sequence == resolution.sequence) {
        if (fact.value != resolution.value) {
          resolution.state = SubjectState::CONFLICT;
          return;
        }
        ++resolution.sources;
        return;
      }
      return;  // superseded observation
    }
    resolution.state = SubjectState::RESOLVED;
    resolution.value = fact.value;
    resolution.generation = fact.generation;
    resolution.sequence = fact.sequence;
    resolution.sources = 1;
  }

  const ResolutionTable& table() const { return table_; }

 private:
  void downgrade(SubjectResolution& resolution, SubjectState state) {
    if (resolution.state == SubjectState::RESOLVED) return;
    if (state_priority(state) > state_priority(resolution.state)) {
      resolution.state = state;
    }
  }

  bool value_in_domain(const EvidenceFact& fact) const {
    switch (fact.kind) {
      case EvidenceKind::LINK_OPERATIONAL: {
        const std::size_t index = indexer_.link(LinkId::from_value(fact.subject.id));
        return index != kNpos && fact.value <= 1;
      }
      case EvidenceKind::NODE_OPERATIONAL: {
        const std::size_t index = indexer_.node(NodeId::from_value(fact.subject.id));
        return index != kNpos && fact.value <= 1;
      }
      case EvidenceKind::SERVICE_REACHABLE_ENDPOINTS: {
        const std::size_t index = indexer_.service(ServiceId::from_value(fact.subject.id));
        return index != kNpos && fact.value <= definition_.services[index].max_reachable &&
               fact.value <= limits_.max_service_endpoints;
      }
      case EvidenceKind::RESOURCE_AVAILABLE_UNITS: {
        const std::size_t index = indexer_.resource(ResourceId::from_value(fact.subject.id));
        return index != kNpos && fact.value <= definition_.resources[index].capacity;
      }
      case EvidenceKind::RESOURCE_RESTORED: {
        const std::size_t index = indexer_.resource(ResourceId::from_value(fact.subject.id));
        return index != kNpos && fact.value <= 1;
      }
      case EvidenceKind::COUNT:
        return false;
    }
    return false;
  }

  const FabricDefinition& definition_;
  const Indexer& indexer_;
  const AuthorityVector& authority_;
  const ModelLimits& limits_;
  ResolutionTable table_;
};

EvidenceKind evidence_kind_for_precondition(PreconditionKind kind) {
  switch (kind) {
    case PreconditionKind::LINK_OPERATIONAL:
    case PreconditionKind::LINK_NOT_OPERATIONAL:
      return EvidenceKind::LINK_OPERATIONAL;
    case PreconditionKind::NODE_OPERATIONAL:
    case PreconditionKind::NODE_NOT_OPERATIONAL:
      return EvidenceKind::NODE_OPERATIONAL;
    case PreconditionKind::SERVICE_REACHABLE_AT_LEAST:
    case PreconditionKind::SERVICE_REACHABLE_AT_MOST:
      return EvidenceKind::SERVICE_REACHABLE_ENDPOINTS;
    case PreconditionKind::RESOURCE_AVAILABLE_AT_LEAST:
      return EvidenceKind::RESOURCE_AVAILABLE_UNITS;
    case PreconditionKind::ACTION_EXECUTED_AT_LEAST:
    case PreconditionKind::COUNT:
      break;
  }
  return EvidenceKind::COUNT;
}

FabricState materialise_state(const FabricDefinition& definition,
                              const Indexer& indexer,
                              const ResolutionTable& table) {
  FabricState state;
  state.node_operational.assign(definition.nodes.size(), 0);
  state.link_operational.assign(definition.links.size(), 0);
  state.resource_restored.assign(definition.resources.size(), 0);
  state.resource_available.assign(definition.resources.size(), 0);
  state.service_reachable.assign(definition.services.size(), 0);
  state.action_occurrences.assign(definition.actions.size(), 0);
  state.node_known.assign(definition.nodes.size(), 0);
  state.link_known.assign(definition.links.size(), 0);
  state.resource_known.assign(definition.resources.size(), 0);
  state.service_known.assign(definition.services.size(), 0);
  for (std::size_t index = 0; index < definition.resources.size(); ++index) {
    state.resource_available[index] = definition.resources[index].capacity;
  }
  for (const auto& entry : table) {
    const SubjectResolution& resolution = entry.second;
    if (resolution.state != SubjectState::RESOLVED) continue;
    const std::size_t index = indexer.subject_index(resolution.subject);
    if (index == kNpos) continue;
    switch (resolution.kind) {
      case EvidenceKind::LINK_OPERATIONAL:
        state.link_operational[index] = static_cast<std::uint8_t>(resolution.value != 0 ? 1 : 0);
        state.link_known[index] = 1;
        break;
      case EvidenceKind::NODE_OPERATIONAL:
        state.node_operational[index] = static_cast<std::uint8_t>(resolution.value != 0 ? 1 : 0);
        state.node_known[index] = 1;
        break;
      case EvidenceKind::SERVICE_REACHABLE_ENDPOINTS:
        state.service_reachable[index] = static_cast<std::uint32_t>(resolution.value);
        state.service_known[index] = 1;
        break;
      case EvidenceKind::RESOURCE_AVAILABLE_UNITS:
        state.resource_available[index] = static_cast<std::uint32_t>(resolution.value);
        state.resource_known[index] = 1;
        break;
      case EvidenceKind::RESOURCE_RESTORED:
        state.resource_restored[index] = static_cast<std::uint8_t>(resolution.value != 0 ? 1 : 0);
        state.resource_known[index] = 1;
        break;
      case EvidenceKind::COUNT:
        break;
    }
  }
  return state;
}

// ---------------------------------------------------------------------------
// Compiled static view of the definition (removes per-transition scans)
// ---------------------------------------------------------------------------

struct Compiled {
  std::vector<std::vector<std::uint32_t>> action_dependency_indices;
  std::vector<std::vector<std::uint32_t>> action_group_indices;
  std::vector<std::vector<std::uint32_t>> action_resource_indices;
  std::vector<std::vector<std::uint32_t>> group_members;
  std::uint64_t absolute_step_bound = 0;
  bool occurrence_bound_overflows = false;

  void build(const FabricDefinition& def, const Indexer& indexer) {
    action_dependency_indices.assign(def.actions.size(), {});
    action_group_indices.assign(def.actions.size(), {});
    action_resource_indices.assign(def.actions.size(), {});
    group_members.assign(def.exclusion_groups.size(), {});
    absolute_step_bound = 0;
    occurrence_bound_overflows = false;
    for (std::size_t index = 0; index < def.actions.size(); ++index) {
      const ActionSpec& action = def.actions[index];
      std::uint64_t sum = 0;
      if (add_overflow(absolute_step_bound, action.max_occurrences, &sum)) {
        occurrence_bound_overflows = true;
      } else {
        absolute_step_bound = sum;
      }
      for (const ActionDependency& dependency : action.dependencies) {
        action_dependency_indices[index].push_back(
            static_cast<std::uint32_t>(indexer.action(dependency.predecessor)));
      }
      for (const ResourceUse& use : action.resource_uses) {
        action_resource_indices[index].push_back(
            static_cast<std::uint32_t>(indexer.resource(use.resource)));
      }
      for (const ExclusionGroupId& group : action.exclusion_groups) {
        for (std::size_t group_index = 0; group_index < def.exclusion_groups.size(); ++group_index) {
          if (def.exclusion_groups[group_index].id == group) {
            action_group_indices[index].push_back(static_cast<std::uint32_t>(group_index));
            group_members[group_index].push_back(static_cast<std::uint32_t>(index));
            break;
          }
        }
      }
    }
  }
};

// ---------------------------------------------------------------------------
// State dependent objective components
// ---------------------------------------------------------------------------

std::uint64_t incompleteness(const FabricDefinition& definition, const FabricState& state) {
  std::uint64_t total = 0;
  for (std::size_t index = 0; index < definition.services.size(); ++index) {
    const ServiceSpec& service = definition.services[index];
    if (service.target_reachable == 0) continue;
    if (state.service_known[index] == 0) {
      // UNKNOWN reachability is accounted at the worst case so that a plan which
      // establishes the value is never scored worse than one that leaves it open.
      total += service.target_reachable;
      continue;
    }
    if (state.service_reachable[index] < service.target_reachable) {
      total += static_cast<std::uint64_t>(service.target_reachable - state.service_reachable[index]);
    }
  }
  return total;
}

std::uint64_t floor_gap(const FabricDefinition& definition, const FabricState& state) {
  std::uint64_t total = 0;
  for (std::size_t index = 0; index < definition.services.size(); ++index) {
    const ServiceSpec& service = definition.services[index];
    if (service.required_reachable == 0) continue;
    if (state.service_known[index] == 0) {
      total += service.required_reachable;
      continue;
    }
    if (state.service_reachable[index] < service.required_reachable) {
      total += static_cast<std::uint64_t>(service.required_reachable -
                                          state.service_reachable[index]);
    }
  }
  return total;
}

// ---------------------------------------------------------------------------
// Transition and search
// ---------------------------------------------------------------------------

struct Transition {
  bool admissible = false;
  bool blocked_by_unknown = false;
  bool blocked_by_policy = false;
  bool blocked_by_safety = false;
  ReasonCode reason = ReasonCode::NONE;
  Subject blocking_subject{};
  FabricState state;
  HoldProfile holds;
  ObjectiveVector delta{};
  std::vector<EvidenceBinding> bindings;
  std::uint32_t occurrence = 0;
  std::uint64_t start_tick = 0;
  std::uint64_t end_tick = 0;
};

struct Node {
  FabricState state;
  HoldProfile holds;
  std::uint64_t parent = kNoParent;
  std::uint32_t action_index = 0;
  std::uint32_t depth = 0;
  std::uint64_t incompleteness_now = 0;
  ObjectiveVector objective{};
};

struct SearchOutcome {
  bool found = false;
  bool budget_exhausted = false;
  bool frontier_emptied = false;
  bool accounting_overflow = false;
  ReasonCode limit_reason = ReasonCode::NONE;
  std::uint64_t plan_node = 0;
  std::uint64_t nodes_expanded = 0;
  std::uint64_t nodes_generated = 0;
  std::uint64_t nodes_pruned_by_policy = 0;
  std::uint64_t nodes_pruned_by_safety = 0;
  std::uint64_t nodes_pruned_by_unknown = 0;
  std::uint64_t states_revisited = 0;
  std::uint64_t frontier_high_water = 0;
  std::uint64_t reachable_states = 0;
  std::uint64_t effective_step_bound = 0;
  bool step_bound_binding = false;
};

class Search {
 public:
  Search(const FabricDefinition& definition,
         const Indexer& indexer,
         const Compiled& compiled,
         const PlanPolicy& policy,
         const FabricState& initial_state,
         const ResolutionTable& resolutions)
      : definition_(definition),
        indexer_(indexer),
        compiled_(compiled),
        policy_(policy),
        resolutions_(resolutions),
        root_state_(initial_state) {
    const std::uint64_t absolute =
        compiled.occurrence_bound_overflows ? UINT64_MAX : compiled.absolute_step_bound;
    outcome_.effective_step_bound = std::min<std::uint64_t>(policy.max_plan_steps, absolute);
    outcome_.step_bound_binding = policy.max_plan_steps < absolute;
  }

  const SearchOutcome& run() {
    Node root;
    root.state = root_state_;
    root.incompleteness_now = incompleteness(definition_, root.state);
    arena_.push_back(std::move(root));
    visited_.emplace(key_of(arena_[0]), 0);
    frontier_.insert(0);

    while (!frontier_.empty()) {
      const std::uint64_t current_index = *frontier_.begin();
      frontier_.erase(frontier_.begin());
      const Node& current = arena_[current_index];
      const std::vector<std::uint8_t> key = key_of(current);
      const auto best = visited_.find(key);
      if (best != visited_.end() && best->second != current_index) {
        ++outcome_.states_revisited;
        continue;
      }
      if (goals_satisfied(current.state)) {
        outcome_.found = true;
        outcome_.plan_node = current_index;
        return finalise();
      }
      if (outcome_.nodes_expanded >= policy_.max_nodes_expanded) {
        outcome_.budget_exhausted = true;
        outcome_.limit_reason = ReasonCode::SEARCH_BUDGET_EXHAUSTED;
        break;
      }
      ++outcome_.nodes_expanded;
      if (current.depth >= outcome_.effective_step_bound) {
        ++outcome_.nodes_pruned_by_policy;
        continue;
      }
      for (std::uint32_t action_index = 0;
           action_index < static_cast<std::uint32_t>(definition_.actions.size());
           ++action_index) {
        Transition transition = apply(current, action_index);
        if (!transition.admissible) {
          if (transition.blocked_by_unknown) {
            ++outcome_.nodes_pruned_by_unknown;
          } else if (transition.blocked_by_policy) {
            ++outcome_.nodes_pruned_by_policy;
          } else if (transition.blocked_by_safety) {
            ++outcome_.nodes_pruned_by_safety;
          }
          continue;
        }
        if (outcome_.nodes_generated >= policy_.max_generated_states) {
          outcome_.budget_exhausted = true;
          outcome_.limit_reason = ReasonCode::SEARCH_BUDGET_EXHAUSTED;
          return finalise();
        }
        ++outcome_.nodes_generated;

        Node child;
        child.state = transition.state;
        child.holds = transition.holds;
        child.parent = current_index;
        child.action_index = action_index;
        child.depth = current.depth + 1;
        child.incompleteness_now = incompleteness(definition_, child.state);
        ObjectiveVector summed;
        if (!ObjectiveVector::add(current.objective, transition.delta, &summed)) {
          outcome_.accounting_overflow = true;
          outcome_.budget_exhausted = true;
          outcome_.limit_reason = ReasonCode::SEARCH_BUDGET_EXHAUSTED;
          return finalise();
        }
        child.objective = summed;
        const std::uint64_t child_index = arena_.size();
        const std::vector<std::uint8_t> child_key = key_of(child);
        const auto existing = visited_.find(child_key);
        if (existing != visited_.end()) {
          const Node& incumbent = arena_[existing->second];
          const int objective_order = compare_objective(child.objective, incumbent.objective);
          // The child is not in the arena yet, so its encoding is derived from
          // its parent rather than from an index that does not exist.
          bool better = objective_order < 0;
          if (objective_order == 0) {
            std::vector<ActionId> child_encoding = encoding_of(current_index);
            child_encoding.push_back(definition_.actions[action_index].id);
            better = compare_encoding(child_encoding, encoding_of(existing->second)) < 0;
          }
          if (!better) {
            ++outcome_.states_revisited;
            continue;
          }
        }
        arena_.push_back(std::move(child));
        visited_[child_key] = child_index;
        frontier_.insert(child_index);
        if (frontier_.size() > outcome_.frontier_high_water) {
          outcome_.frontier_high_water = frontier_.size();
        }
        if (frontier_.size() > policy_.max_frontier_entries) {
          outcome_.budget_exhausted = true;
          outcome_.limit_reason = ReasonCode::SEARCH_BUDGET_EXHAUSTED;
          return finalise();
        }
      }
    }
    if (!outcome_.budget_exhausted) outcome_.frontier_emptied = true;
    return finalise();
  }

  const ObjectiveVector& plan_objective() const { return arena_[outcome_.plan_node].objective; }

  std::vector<ActionId> plan_encoding() const {
    std::vector<ActionId> encoding;
    std::uint64_t index = outcome_.plan_node;
    while (index != kNoParent && arena_[index].parent != kNoParent) {
      encoding.push_back(definition_.actions[arena_[index].action_index].id);
      index = arena_[index].parent;
    }
    std::reverse(encoding.begin(), encoding.end());
    return encoding;
  }

  /// Replays an encoding from the pristine initial state and produces the plan
  /// steps, evidence bindings and checked tick/objective accounting.
  Status replay(const std::vector<ActionId>& encoding,
                std::vector<PlanStep>* steps,
                ObjectiveVector* objective) const {
    Node node;
    node.state = root_state_;
    node.incompleteness_now = incompleteness(definition_, node.state);
    ObjectiveVector accumulated{};
    for (std::size_t position = 0; position < encoding.size(); ++position) {
      const std::size_t action_index = indexer_.action(encoding[position]);
      if (action_index == kNpos) {
        return Status::error(StatusCode::STATE_MISMATCH, "replay encountered an unknown action");
      }
      Transition transition = apply(node, static_cast<std::uint32_t>(action_index));
      if (!transition.admissible) {
        return Status::error(StatusCode::STATE_MISMATCH,
                             "replay rejected a step the search accepted");
      }
      const ActionSpec& action = definition_.actions[action_index];
      PlanStep step;
      step.index = static_cast<std::uint32_t>(position);
      step.action = encoding[position];
      step.occurrence = transition.occurrence;
      step.start_tick = transition.start_tick;
      step.end_tick = transition.end_tick;
      step.required_domain = action.required_domain;
      step.required_level = action.required_level;
      step.issued_level = AuthorityLevel::RECOMMENDATION;
      step.evidence = transition.bindings;
      step.irreversible = action.reversibility == Reversibility::IRREVERSIBLE;
      step.compensation = action.compensation;
      steps->push_back(std::move(step));

      node.state = transition.state;
      node.holds = transition.holds;
      node.incompleteness_now = incompleteness(definition_, node.state);
      ObjectiveVector summed;
      if (!ObjectiveVector::add(accumulated, transition.delta, &summed)) {
        return Status::error(StatusCode::OUT_OF_RANGE, "objective overflow during replay");
      }
      accumulated = summed;
    }
    *objective = accumulated;
    return Status::success();
  }

 private:
  const SearchOutcome& finalise() {
    outcome_.reachable_states = visited_.size();
    return outcome_;
  }

  std::vector<std::uint8_t> key_of(const Node& node) const {
    CanonicalWriter writer;
    node.state.encode(writer);
    writer.u32(static_cast<std::uint32_t>(node.holds.size()));
    for (const ResourceHold& hold : node.holds) {
      writer.u32(hold.resource_index);
      writer.u32(hold.units);
      writer.u32(hold.remaining_steps);
    }
    return writer.take();
  }

  std::vector<ActionId> encoding_of(std::uint64_t index) const {
    std::vector<ActionId> encoding;
    while (index != kNoParent && arena_[index].parent != kNoParent) {
      encoding.push_back(definition_.actions[arena_[index].action_index].id);
      index = arena_[index].parent;
    }
    std::reverse(encoding.begin(), encoding.end());
    return encoding;
  }

  bool goals_satisfied(const FabricState& state) const {
    for (const GoalSpec& goal : definition_.goals) {
      const std::size_t index = indexer_.subject_index(goal.subject);
      if (index == kNpos) return false;
      switch (goal.kind) {
        case GoalKind::LINK_OPERATIONAL:
          if (state.link_known[index] == 0 || state.link_operational[index] == 0) return false;
          break;
        case GoalKind::NODE_OPERATIONAL:
          if (state.node_known[index] == 0 || state.node_operational[index] == 0) return false;
          break;
        case GoalKind::RESOURCE_RESTORED:
          if (state.resource_known[index] == 0 || state.resource_restored[index] == 0) return false;
          break;
        case GoalKind::SERVICE_REACHABLE_AT_LEAST:
          if (state.service_known[index] == 0) return false;
          if (state.service_reachable[index] < goal.value) return false;
          break;
        case GoalKind::COUNT:
          return false;
      }
    }
    return true;
  }

  bool precondition_holds(const FabricState& state,
                          const Precondition& precondition,
                          bool* known) const {
    const std::size_t index = indexer_.subject_index(precondition.subject);
    if (index == kNpos) {
      *known = false;
      return false;
    }
    switch (precondition.kind) {
      case PreconditionKind::LINK_OPERATIONAL:
        *known = state.link_known[index] != 0;
        return *known && state.link_operational[index] != 0;
      case PreconditionKind::LINK_NOT_OPERATIONAL:
        *known = state.link_known[index] != 0;
        return *known && state.link_operational[index] == 0;
      case PreconditionKind::NODE_OPERATIONAL:
        *known = state.node_known[index] != 0;
        return *known && state.node_operational[index] != 0;
      case PreconditionKind::NODE_NOT_OPERATIONAL:
        *known = state.node_known[index] != 0;
        return *known && state.node_operational[index] == 0;
      case PreconditionKind::SERVICE_REACHABLE_AT_LEAST:
        *known = state.service_known[index] != 0;
        return *known && state.service_reachable[index] >= precondition.value;
      case PreconditionKind::SERVICE_REACHABLE_AT_MOST:
        *known = state.service_known[index] != 0;
        return *known && state.service_reachable[index] <= precondition.value;
      case PreconditionKind::RESOURCE_AVAILABLE_AT_LEAST:
        *known = state.resource_known[index] != 0;
        return *known && state.resource_available[index] >= precondition.value;
      case PreconditionKind::ACTION_EXECUTED_AT_LEAST:
        *known = true;
        return state.action_occurrences[index] >= precondition.value;
      case PreconditionKind::COUNT:
        *known = false;
        return false;
    }
    *known = false;
    return false;
  }

  const SubjectResolution* resolution_for(const Precondition& precondition) const {
    const EvidenceKind kind = evidence_kind_for_precondition(precondition.kind);
    if (kind == EvidenceKind::COUNT) return nullptr;
    const auto it = resolutions_.find(EvidenceKey{kind, precondition.subject});
    if (it == resolutions_.end()) return nullptr;
    return &it->second;
  }

  Transition apply(const Node& current, std::uint32_t action_index) const {
    Transition transition;
    const ActionSpec& action = definition_.actions[action_index];
    const std::vector<std::uint32_t>& dependency_indices =
        compiled_.action_dependency_indices[action_index];
    const std::vector<std::uint32_t>& group_indices = compiled_.action_group_indices[action_index];
    const std::vector<std::uint32_t>& resource_indices =
        compiled_.action_resource_indices[action_index];

    FabricState next = current.state;
    const std::uint32_t executed = next.action_occurrences[action_index];
    if (executed >= action.max_occurrences) {
      transition.reason = ReasonCode::VALIDATION_OCCURRENCE_EXCEEDED;
      return transition;
    }
    for (std::size_t index = 0; index < action.dependencies.size(); ++index) {
      const std::uint32_t predecessor = dependency_indices[index];
      if (predecessor >= definition_.actions.size() ||
          next.action_occurrences[predecessor] < action.dependencies[index].min_occurrences) {
        transition.reason = ReasonCode::VALIDATION_ORDERING_VIOLATION;
        return transition;
      }
    }
    if (executed == 0) {
      for (const std::uint32_t group_index : group_indices) {
        const ExclusionGroup& group = definition_.exclusion_groups[group_index];
        std::uint32_t selected = 0;
        for (const std::uint32_t member : compiled_.group_members[group_index]) {
          if (next.action_occurrences[member] > 0) ++selected;
        }
        if (selected >= group.max_selected) {
          transition.reason = ReasonCode::VALIDATION_EXCLUSION_VIOLATION;
          return transition;
        }
      }
    }

    std::vector<EvidenceBinding> bindings;
    for (const Precondition& precondition : action.preconditions) {
      bool known = false;
      const bool holds = precondition_holds(next, precondition, &known);
      if (!known) {
        // Fail closed: an UNKNOWN subject never satisfies a precondition.
        transition.blocked_by_unknown = true;
        transition.blocking_subject = precondition.subject;
        transition.reason = ReasonCode::EVIDENCE_SUBJECT_MISSING;
        return transition;
      }
      if (!holds) {
        transition.reason = ReasonCode::VALIDATION_PRECONDITION_UNMET;
        return transition;
      }
      if (precondition.kind == PreconditionKind::ACTION_EXECUTED_AT_LEAST) continue;
      const SubjectResolution* resolution = resolution_for(precondition);
      if (resolution != nullptr && resolution->state == SubjectState::RESOLVED) {
        bindings.push_back(
            EvidenceBinding{resolution->kind, resolution->subject, resolution->generation});
      }
    }
    std::sort(bindings.begin(), bindings.end());
    bindings.erase(std::unique(bindings.begin(), bindings.end()), bindings.end());

    for (std::size_t index = 0; index < action.resource_uses.size(); ++index) {
      const std::uint32_t resource_index = resource_indices[index];
      const ResourceSpec& resource = definition_.resources[resource_index];
      const ResourceUse& use = action.resource_uses[index];
      if (resource.kind == ResourceKind::CONSUMABLE) {
        if (next.resource_known[resource_index] == 0) {
          transition.blocked_by_unknown = true;
          transition.blocking_subject = subject_of(resource.id);
          return transition;
        }
        if (next.resource_available[resource_index] < use.units) {
          transition.reason = ReasonCode::VALIDATION_RESOURCE_VIOLATION;
          return transition;
        }
      } else {
        std::uint64_t held = 0;
        for (const ResourceHold& hold : current.holds) {
          if (hold.resource_index == resource_index) held += hold.units;
        }
        if (held + use.units > resource.capacity) {
          transition.reason = ReasonCode::VALIDATION_RESOURCE_VIOLATION;
          return transition;
        }
      }
    }

    const std::uint64_t floor_gap_before = floor_gap(definition_, current.state);
    const std::uint64_t incompleteness_before = current.incompleteness_now;

    for (const Effect& effect : action.effects) {
      const std::size_t index = indexer_.subject_index(effect.subject);
      if (index == kNpos) {
        transition.reason = ReasonCode::REQUEST_UNSUPPORTED_PROBLEM;
        return transition;
      }
      switch (effect.kind) {
        case EffectKind::SET_LINK_OPERATIONAL:
          next.link_operational[index] = static_cast<std::uint8_t>(effect.value != 0 ? 1 : 0);
          next.link_known[index] = 1;
          break;
        case EffectKind::SET_NODE_OPERATIONAL:
          next.node_operational[index] = static_cast<std::uint8_t>(effect.value != 0 ? 1 : 0);
          next.node_known[index] = 1;
          break;
        case EffectKind::SET_SERVICE_REACHABLE:
          if (static_cast<std::uint64_t>(effect.value) >
              definition_.services[index].max_reachable) {
            transition.blocked_by_safety = true;
            transition.reason = ReasonCode::VALIDATION_SAFETY_VIOLATION;
            return transition;
          }
          next.service_reachable[index] = static_cast<std::uint32_t>(effect.value);
          next.service_known[index] = 1;
          break;
        case EffectKind::SERVICE_REACHABLE_DELTA: {
          if (next.service_known[index] == 0) {
            if (definition_.services[index].required_reachable > 0) {
              transition.blocked_by_unknown = true;
              transition.blocking_subject = effect.subject;
              return transition;
            }
            break;
          }
          const std::int64_t base = static_cast<std::int64_t>(next.service_reachable[index]);
          const std::int64_t updated = base + effect.value;
          if (updated < 0 ||
              static_cast<std::uint64_t>(updated) > definition_.services[index].max_reachable) {
            transition.blocked_by_safety = true;
            transition.reason = ReasonCode::VALIDATION_SAFETY_VIOLATION;
            return transition;
          }
          next.service_reachable[index] = static_cast<std::uint32_t>(updated);
          break;
        }
        case EffectKind::MARK_RESOURCE_RESTORED:
          next.resource_restored[index] = 1;
          next.resource_known[index] = 1;
          break;
        case EffectKind::SET_RESOURCE_AVAILABLE:
          if (static_cast<std::uint64_t>(effect.value) >
              definition_.resources[index].capacity) {
            transition.reason = ReasonCode::VALIDATION_RESOURCE_VIOLATION;
            return transition;
          }
          next.resource_available[index] = static_cast<std::uint32_t>(effect.value);
          next.resource_known[index] = 1;
          break;
        case EffectKind::COUNT:
          transition.reason = ReasonCode::REQUEST_UNSUPPORTED_PROBLEM;
          return transition;
      }
    }

    for (std::size_t index = 0; index < action.resource_uses.size(); ++index) {
      const std::uint32_t resource_index = resource_indices[index];
      if (definition_.resources[resource_index].kind == ResourceKind::CONSUMABLE) {
        next.resource_available[resource_index] -= action.resource_uses[index].units;
      }
    }

    if (floor_gap(definition_, next) > floor_gap_before) {
      transition.blocked_by_safety = true;
      transition.reason = ReasonCode::VALIDATION_SAFETY_VIOLATION;
      return transition;
    }

    // Hold bookkeeping. A usage at step j covers steps j .. j+hold_steps-1, so
    // the child carries hold_steps-1 remaining future steps; a usage whose window
    // covers only its own step is not carried forward at all.
    HoldProfile holds;
    holds.reserve(current.holds.size() + action.resource_uses.size());
    for (const ResourceHold& hold : current.holds) {
      // remaining_steps counts the future steps the hold still covers; entries
      // that would reach zero are dropped rather than counted once more.
      if (hold.remaining_steps > 1) {
        ResourceHold decayed = hold;
        decayed.remaining_steps -= 1;
        holds.push_back(decayed);
      }
    }
    for (std::size_t index = 0; index < action.resource_uses.size(); ++index) {
      const std::uint32_t resource_index = resource_indices[index];
      const ResourceSpec& resource = definition_.resources[resource_index];
      if (resource.kind != ResourceKind::REUSABLE) continue;
      if (resource.hold_steps <= 1) continue;  // covers only the executing step
      ResourceHold hold;
      hold.resource_index = resource_index;
      hold.units = action.resource_uses[index].units;
      hold.remaining_steps = resource.hold_steps - 1;
      holds.push_back(hold);
    }
    std::sort(holds.begin(), holds.end());

    if (action.reversibility == Reversibility::IRREVERSIBLE &&
        !policy_.allow_irreversible_actions) {
      transition.blocked_by_policy = true;
      transition.reason = ReasonCode::REQUEST_POLICY_RESTRICTED_ACTION;
      return transition;
    }

    next.action_occurrences[action_index] = executed + 1;
    std::uint64_t tick = 0;
    if (add_overflow(next.tick, action.duration_ticks, &tick)) {
      transition.reason = ReasonCode::REQUEST_UNSUPPORTED_PROBLEM;
      return transition;
    }
    next.tick = tick;

    transition.admissible = true;
    transition.state = std::move(next);
    transition.holds = std::move(holds);
    transition.bindings = std::move(bindings);
    transition.occurrence = executed + 1;
    transition.start_tick = current.state.tick;
    transition.end_tick = tick;
    transition.delta = ObjectiveVector{};
    transition.delta[3] = action.blast_radius;
    transition.delta[4] = 1;
    transition.delta[5] = action.disruption;
    transition.delta[6] = action.cost_units;
    transition.delta[7] = action.duration_ticks;
    const std::uint64_t after = incompleteness(definition_, transition.state);
    transition.delta[2] = after > incompleteness_before ? after - incompleteness_before : 0;
    return transition;
  }

  const FabricDefinition& definition_;
  const Indexer& indexer_;
  const Compiled& compiled_;
  const PlanPolicy& policy_;
  const ResolutionTable& resolutions_;
  FabricState root_state_;

  // A deque is used deliberately: references to already expanded nodes must stay
  // valid while the arena grows during expansion of the current node.
  std::deque<Node> arena_;
  std::map<std::vector<std::uint8_t>, std::uint64_t> visited_;
  struct FrontierLess {
    const Search* search = nullptr;
    bool operator()(std::uint64_t a, std::uint64_t b) const {
      const Node& left = search->arena_[a];
      const Node& right = search->arena_[b];
      const int order = compare_objective(left.objective, right.objective);
      if (order != 0) return order < 0;
      return compare_encoding(search->encoding_of(a), search->encoding_of(b)) < 0;
    }
  };
  std::set<std::uint64_t, FrontierLess> frontier_{FrontierLess{this}};
  SearchOutcome outcome_{};
};

// ---------------------------------------------------------------------------
// Static proofs
// ---------------------------------------------------------------------------

/// Finds a dependency cycle over actions. Any cycle proves that no execution
/// order exists, independently of the search budget.
bool find_dependency_cycle(const FabricDefinition& definition,
                           const Indexer& indexer,
                           std::vector<ActionId>* cycle) {
  const std::size_t count = definition.actions.size();
  std::vector<std::vector<std::size_t>> successors(count);
  for (std::size_t index = 0; index < count; ++index) {
    for (const ActionDependency& dependency : definition.actions[index].dependencies) {
      const std::size_t predecessor = indexer.action(dependency.predecessor);
      if (predecessor != kNpos) successors[predecessor].push_back(index);
    }
  }
  std::vector<int> colour(count, 0);
  std::vector<std::size_t> path;
  struct Frame {
    std::size_t node = 0;
    std::size_t next = 0;
  };
  std::vector<Frame> frames;
  for (std::size_t start = 0; start < count; ++start) {
    if (colour[start] != 0) continue;
    frames.push_back(Frame{start, 0});
    colour[start] = 1;
    path.push_back(start);
    while (!frames.empty()) {
      Frame& frame = frames.back();
      if (frame.next < successors[frame.node].size()) {
        const std::size_t next = successors[frame.node][frame.next++];
        if (colour[next] == 1) {
          const auto it = std::find(path.begin(), path.end(), next);
          for (auto walk = it; walk != path.end(); ++walk) {
            cycle->push_back(definition.actions[*walk].id);
          }
          cycle->push_back(definition.actions[next].id);
          return true;
        }
        if (colour[next] == 0) {
          colour[next] = 1;
          path.push_back(next);
          frames.push_back(Frame{next, 0});
        }
      } else {
        colour[frame.node] = 2;
        path.pop_back();
        frames.pop_back();
      }
    }
  }
  return false;
}

/// Structural upper bound on the value a goal subject can ever reach. Only used
/// to prove infeasibility when the bound is provably below the goal.
bool goal_upper_bound(const FabricDefinition& definition,
                      const Indexer& indexer,
                      const FabricState& initial,
                      const GoalSpec& goal,
                      std::uint64_t* bound) {
  const std::size_t subject = indexer.subject_index(goal.subject);
  if (subject == kNpos) return false;
  switch (goal.kind) {
    case GoalKind::LINK_OPERATIONAL:
    case GoalKind::NODE_OPERATIONAL:
    case GoalKind::RESOURCE_RESTORED: {
      bool writer = false;
      for (const ActionSpec& action : definition.actions) {
        for (const Effect& effect : action.effects) {
          if (effect.subject != goal.subject) continue;
          if (goal.kind == GoalKind::LINK_OPERATIONAL &&
              effect.kind == EffectKind::SET_LINK_OPERATIONAL && effect.value == 1) {
            writer = true;
          }
          if (goal.kind == GoalKind::NODE_OPERATIONAL &&
              effect.kind == EffectKind::SET_NODE_OPERATIONAL && effect.value == 1) {
            writer = true;
          }
          if (goal.kind == GoalKind::RESOURCE_RESTORED &&
              effect.kind == EffectKind::MARK_RESOURCE_RESTORED) {
            writer = true;
          }
        }
      }
      if (writer) return false;
      switch (goal.kind) {
        case GoalKind::LINK_OPERATIONAL:
          if (initial.link_known[subject] == 0) return false;
          *bound = initial.link_operational[subject];
          return true;
        case GoalKind::NODE_OPERATIONAL:
          if (initial.node_known[subject] == 0) return false;
          *bound = initial.node_operational[subject];
          return true;
        default:
          if (initial.resource_known[subject] == 0) return false;
          *bound = initial.resource_restored[subject];
          return true;
      }
    }
    case GoalKind::SERVICE_REACHABLE_AT_LEAST: {
      const ServiceSpec& service = definition.services[subject];
      std::uint64_t best = initial.service_known[subject] != 0
                               ? initial.service_reachable[subject]
                               : service.max_reachable;
      std::uint64_t delta_total = 0;
      for (const ActionSpec& action : definition.actions) {
        std::uint64_t action_positive = 0;
        for (const Effect& effect : action.effects) {
          if (effect.subject != goal.subject) continue;
          if (effect.kind == EffectKind::SET_SERVICE_REACHABLE) {
            if (effect.value >= 0 && static_cast<std::uint64_t>(effect.value) > best) {
              best = static_cast<std::uint64_t>(effect.value);
            }
          } else if (effect.kind == EffectKind::SERVICE_REACHABLE_DELTA && effect.value > 0) {
            std::uint64_t sum = 0;
            if (add_overflow(action_positive, static_cast<std::uint64_t>(effect.value), &sum)) {
              return false;
            }
            action_positive = sum;
          }
        }
        std::uint64_t contribution = 0;
        if (mul_overflow(action_positive, action.max_occurrences, &contribution)) return false;
        std::uint64_t sum = 0;
        if (add_overflow(delta_total, contribution, &sum)) return false;
        delta_total = sum;
      }
      std::uint64_t reachable = 0;
      if (add_overflow(best, delta_total, &reachable)) return false;
      if (reachable > service.max_reachable) reachable = service.max_reachable;
      *bound = reachable;
      return true;
    }
    case GoalKind::COUNT:
      return false;
  }
  return false;
}

PlanDecision decision_for_binding(BindingState state) {
  switch (state) {
    case BindingState::CURRENT: return PlanDecision::PLAN_FOUND;
    case BindingState::STALE: return PlanDecision::REJECTED_STALE_AUTHORITY;
    case BindingState::UNKNOWN: return PlanDecision::REJECTED_UNKNOWN_AUTHORITY;
    case BindingState::CONFLICT: return PlanDecision::REJECTED_CONFLICTING_AUTHORITY;
    case BindingState::INVALID: return PlanDecision::REJECTED_INVALID_REQUEST;
    case BindingState::UNSUPPORTED: return PlanDecision::REJECTED_UNSUPPORTED_PROBLEM;
    case BindingState::COUNT: return PlanDecision::REJECTED_INVALID_REQUEST;
  }
  return PlanDecision::REJECTED_INVALID_REQUEST;
}

ReasonCode reason_for_binding(BindingState state) {
  switch (state) {
    case BindingState::CURRENT: return ReasonCode::NONE;
    case BindingState::STALE: return ReasonCode::AUTHORITY_BINDING_STALE;
    case BindingState::UNKNOWN: return ReasonCode::AUTHORITY_BINDING_UNKNOWN;
    case BindingState::CONFLICT: return ReasonCode::AUTHORITY_BINDING_CONFLICT;
    case BindingState::INVALID: return ReasonCode::AUTHORITY_BINDING_INVALID;
    case BindingState::UNSUPPORTED: return ReasonCode::AUTHORITY_BINDING_UNSUPPORTED;
    case BindingState::COUNT: return ReasonCode::AUTHORITY_BINDING_INVALID;
  }
  return ReasonCode::AUTHORITY_BINDING_INVALID;
}

std::vector<AuthorityDomain> required_domains(const FabricDefinition& definition,
                                              const EvidenceBundle& evidence) {
  std::vector<AuthorityDomain> domains;
  const auto add = [&domains](AuthorityDomain domain) {
    if (std::find(domains.begin(), domains.end(), domain) == domains.end()) {
      domains.push_back(domain);
    }
  };
  add(AuthorityDomain::FABRIC_STATE);
  add(AuthorityDomain::POLICY);
  if (!evidence.facts.empty()) add(AuthorityDomain::EVIDENCE_INGEST);
  for (const EvidenceFact& fact : evidence.facts) {
    if (fact.kind == EvidenceKind::RESOURCE_AVAILABLE_UNITS ||
        fact.kind == EvidenceKind::RESOURCE_RESTORED) {
      add(AuthorityDomain::RESOURCE_LEASE);
    }
  }
  for (const ActionSpec& action : definition.actions) {
    add(action.required_domain);
  }
  std::sort(domains.begin(), domains.end(), [](AuthorityDomain a, AuthorityDomain b) {
    return static_cast<std::uint8_t>(a) < static_cast<std::uint8_t>(b);
  });
  return domains;
}

}  // namespace

// ---------------------------------------------------------------------------
// Initial state derivation (public entry point)
// ---------------------------------------------------------------------------

Status derive_initial_state(const FabricDefinition& definition,
                            const EvidenceBundle& evidence,
                            const AuthorityVector& authority,
                            const ModelLimits& limits,
                            DerivedState* out) {
  Indexer indexer;
  indexer.build(definition);
  Reconciler reconciler(definition, indexer, authority, limits);
  for (const EvidenceFact& fact : evidence.facts) {
    reconciler.ingest(fact);
  }
  const ResolutionTable& table = reconciler.table();

  DerivedState derived;
  derived.state = materialise_state(definition, indexer, table);
  for (const auto& entry : table) {
    const SubjectResolution& resolution = entry.second;
    if (resolution.state == SubjectState::RESOLVED) {
      derived.generation_index.emplace_back(resolution.subject, resolution.generation);
      continue;
    }
    derived.unresolved.push_back(resolution.subject);
    Explanation explanation;
    explanation.code = reason_for(resolution.state);
    explanation.subject = resolution.subject;
    explanation.text = std::string(to_string(resolution.state)) + " evidence for " +
                       describe(resolution.subject);
    derived.explanations.push_back(std::move(explanation));
  }
  std::sort(derived.generation_index.begin(), derived.generation_index.end());
  derived.generation_index.erase(
      std::unique(derived.generation_index.begin(), derived.generation_index.end()),
      derived.generation_index.end());
  std::sort(derived.unresolved.begin(), derived.unresolved.end());
  derived.unresolved.erase(std::unique(derived.unresolved.begin(), derived.unresolved.end()),
                           derived.unresolved.end());
  *out = std::move(derived);
  return Status::success();
}

bool DerivedState::generation_of(const Subject& subject, Generation* out) const {
  for (const auto& entry : generation_index) {
    if (entry.first == subject) {
      *out = entry.second;
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Planner entry point
// ---------------------------------------------------------------------------

PlanningResult Planner::plan(const PlanRequest& request) const {
  ExplanationLog log(96);
  PlanningResult result;
  result.request = request.id;
  result.coordinator_epoch = request.coordinator_epoch;
  result.boot = request.boot;
  result.attempt = request.attempt;

  // Canonicalise a private copy: results and digests must not depend on the
  // order in which the caller happened to build its containers.
  PlanRequest normalised = request;
  normalised.definition.canonicalise();
  normalised.evidence.canonicalise();
  normalised.authority.canonicalise();
  std::sort(normalised.fences.begin(), normalised.fences.end());
  result.request_digest = normalised.digest();
  const FabricDefinition& definition = normalised.definition;

  const auto conclude = [&result, &log](PlanDecision decision) {
    result.decision = decision;
    if (result.explanations.empty()) result.explanations = log.entries();
    return result;
  };

  if (request.id.is_zero() || request.attempt.is_zero()) {
    log.add(ReasonCode::REQUEST_UNSUPPORTED_PROBLEM,
            "request identity and attempt identity are mandatory and must be non-zero");
    return conclude(PlanDecision::REJECTED_UNSUPPORTED_PROBLEM);
  }
  if (normalised.policy.max_plan_steps == 0 || normalised.policy.max_nodes_expanded == 0 ||
      normalised.policy.max_generated_states == 0 || normalised.policy.max_frontier_entries == 0) {
    log.add(ReasonCode::REQUEST_INVALID_DEFINITION, "policy bounds must be at least one");
    return conclude(PlanDecision::REJECTED_INVALID_REQUEST);
  }
  if (normalised.policy.budget_scale == 0 || normalised.policy.budget_scale > 64) {
    log.add(ReasonCode::REQUEST_UNSUPPORTED_PROBLEM,
            "policy budget_scale is outside the supported range 1..64");
    return conclude(PlanDecision::REJECTED_UNSUPPORTED_PROBLEM);
  }
  {
    ExplanationLog definition_log(32);
    const Status status = validate_definition(definition, limits_, &definition_log);
    if (!status.ok()) {
      log.add(ReasonCode::REQUEST_INVALID_DEFINITION, status.to_string());
      for (const Explanation& explanation : definition_log.entries()) log.add(explanation);
      return conclude(PlanDecision::REJECTED_INVALID_REQUEST);
    }
  }
  if (normalised.authority.coordinator_epoch != normalised.coordinator_epoch ||
      normalised.authority.boot != normalised.boot) {
    log.add(ReasonCode::AUTHORITY_BINDING_INVALID,
            "authority vector belongs to a different coordinator epoch or boot incarnation");
    return conclude(PlanDecision::REJECTED_INVALID_REQUEST);
  }
  if (normalised.evidence.coordinator_epoch != normalised.coordinator_epoch ||
      normalised.evidence.boot != normalised.boot) {
    const bool stale = normalised.evidence.coordinator_epoch < normalised.coordinator_epoch;
    log.add(stale ? ReasonCode::EVIDENCE_SUBJECT_STALE : ReasonCode::EVIDENCE_SUBJECT_INVALID,
            "evidence bundle was not produced under the request coordinator epoch/boot");
    return conclude(stale ? PlanDecision::REJECTED_STALE_AUTHORITY
                          : PlanDecision::REJECTED_INVALID_REQUEST);
  }
  for (const Fence& fence : normalised.fences) {
    if (fence.epoch > normalised.coordinator_epoch) {
      log.add(ReasonCode::REQUEST_FENCED_BY_EPOCH,
              "a fence from a later coordinator epoch revokes this request");
      return conclude(PlanDecision::REJECTED_FENCED);
    }
    if (fence.epoch == normalised.coordinator_epoch && fence.boot != normalised.boot) {
      log.add(ReasonCode::REQUEST_FENCED_BY_EPOCH,
              "a fence from another boot incarnation of the same epoch revokes this request");
      return conclude(PlanDecision::REJECTED_FENCED);
    }
  }
  if (normalised.policy.require_current_authority) {
    const std::vector<AuthorityDomain> domains = required_domains(definition, normalised.evidence);
    for (const AuthorityDomain domain : domains) {
      const BindingState state = evaluate_domain(normalised.authority, domain);
      if (state != BindingState::CURRENT) {
        log.add(reason_for_binding(state),
                std::string("authority domain ") + to_string(domain) + " is " + to_string(state));
        return conclude(decision_for_binding(state));
      }
    }
    for (const ActionSpec& action : definition.actions) {
      const AuthorityBinding* binding = normalised.authority.find(action.required_domain);
      if (binding == nullptr || binding->level < action.required_level) {
        log.add(ReasonCode::AUTHORITY_LEVEL_INSUFFICIENT,
                Subject{SubjectKind::ACTION, action.id.value()}, 0, 0,
                std::string("action requires ") + to_string(action.required_level) + " on " +
                    to_string(action.required_domain) + " but only a weaker level is established");
        return conclude(PlanDecision::REJECTED_UNKNOWN_AUTHORITY);
      }
    }
  }

  Indexer indexer;
  indexer.build(definition);
  Compiled compiled;
  compiled.build(definition, indexer);
  Reconciler reconciler(definition, indexer, normalised.authority, limits_);
  for (const EvidenceFact& fact : normalised.evidence.facts) {
    reconciler.ingest(fact);
  }
  const ResolutionTable& table = reconciler.table();
  const FabricState initial = materialise_state(definition, indexer, table);

  // Subjects a step or a goal actually depends on. A subject that no step and no
  // goal reads cannot turn a proof of infeasibility into an indeterminate answer.
  std::set<Subject> referenced;
  for (const ActionSpec& action : definition.actions) {
    for (const Precondition& precondition : action.preconditions) {
      referenced.insert(precondition.subject);
    }
  }
  for (const GoalSpec& goal : definition.goals) {
    referenced.insert(goal.subject);
  }
  std::set<Subject> unresolved_referenced;
  for (const auto& entry : table) {
    if (entry.second.state == SubjectState::RESOLVED) continue;
    if (referenced.count(entry.second.subject) != 0) {
      unresolved_referenced.insert(entry.second.subject);
      Explanation explanation;
      explanation.code = reason_for(entry.second.state);
      explanation.subject = entry.second.subject;
      explanation.text = std::string(to_string(entry.second.state)) + " evidence for " +
                         describe(entry.second.subject);
      log.add(explanation);
    }
  }
  for (const Subject& subject : referenced) {
    const std::size_t index = indexer.subject_index(subject);
    if (index == kNpos) continue;
    bool established = true;
    switch (subject.kind) {
      case SubjectKind::LINK: established = initial.link_known[index] != 0; break;
      case SubjectKind::NODE: established = initial.node_known[index] != 0; break;
      case SubjectKind::SERVICE: established = initial.service_known[index] != 0; break;
      case SubjectKind::RESOURCE: established = initial.resource_known[index] != 0; break;
      default: break;
    }
    if (!established) {
      unresolved_referenced.insert(subject);
      log.add(ReasonCode::EVIDENCE_SUBJECT_MISSING, subject, 0, 0,
              "no evidence establishes this subject at the granted generation");
    }
  }
  result.unresolved_subjects.assign(unresolved_referenced.begin(), unresolved_referenced.end());

  // Static proofs. A dependency cycle rules out every execution order, and a
  // structural upper bound below a goal value rules the goal out entirely.
  std::vector<ActionId> cycle;
  if (find_dependency_cycle(definition, indexer, &cycle)) {
    InfeasibilityCertificate certificate;
    certificate.kind = ProofKind::DEPENDENCY_CYCLE;
    certificate.request_digest = result.request_digest;
    certificate.policy_digest = normalised.policy.digest();
    certificate.cycle = cycle;
    certificate.assumptions.push_back("action dependencies are unconditional");
    certificate.assumptions.push_back("every action executes at most max_occurrences times");
    certificate.assumptions.push_back(
        "evidence establishes every subject referenced by a precondition or goal");
    Explanation explanation;
    explanation.code = ReasonCode::PROOF_DEPENDENCY_CYCLE;
    explanation.text = "the action dependency relation contains a cycle";
    certificate.explanations.push_back(explanation);
    log.add(explanation);
    result.certificate = std::move(certificate);
    return conclude(PlanDecision::PROVEN_INFEASIBLE);
  }
  for (const GoalSpec& goal : definition.goals) {
    std::uint64_t bound = 0;
    if (!goal_upper_bound(definition, indexer, initial, goal, &bound)) continue;
    if (bound >= goal.value) continue;
    InfeasibilityCertificate certificate;
    certificate.kind = ProofKind::GOAL_UPPER_BOUND;
    certificate.request_digest = result.request_digest;
    certificate.policy_digest = normalised.policy.digest();
    certificate.unreachable_subject = goal.subject;
    certificate.unreachable_value = bound;
    certificate.required_value = goal.value;
    certificate.assumptions.push_back("no action can raise the subject beyond the derived bound");
    certificate.assumptions.push_back("action effects are exactly as declared in the definition");
    certificate.assumptions.push_back(
        "evidence establishes every subject referenced by a precondition or goal");
    Explanation explanation;
    explanation.code = ReasonCode::PROOF_GOAL_UPPER_BOUND;
    explanation.subject = goal.subject;
    explanation.detail_a = bound;
    explanation.detail_b = goal.value;
    explanation.text = "goal value exceeds the structural upper bound of the subject";
    certificate.explanations.push_back(explanation);
    log.add(explanation);
    result.certificate = std::move(certificate);
    return conclude(PlanDecision::PROVEN_INFEASIBLE);
  }

  Search search(definition, indexer, compiled, normalised.policy, initial, table);
  const SearchOutcome& outcome = search.run();
  result.stats.nodes_expanded = outcome.nodes_expanded;
  result.stats.nodes_generated = outcome.nodes_generated;
  result.stats.nodes_pruned_by_dominance = outcome.states_revisited;
  result.stats.nodes_pruned_by_safety = outcome.nodes_pruned_by_safety;
  result.stats.nodes_pruned_by_authority = outcome.nodes_pruned_by_unknown;
  result.stats.nodes_pruned_by_policy = outcome.nodes_pruned_by_policy;
  result.stats.frontier_high_water = outcome.frontier_high_water;
  result.stats.states_revisited = outcome.states_revisited;
  result.stats.budget_nodes = normalised.policy.max_nodes_expanded;
  result.stats.budget_exhausted = outcome.budget_exhausted;
  result.stats.frontier_emptied = outcome.frontier_emptied;

  if (outcome.found) {
    std::vector<PlanStep> steps;
    ObjectiveVector objective{};
    const Status status = search.replay(search.plan_encoding(), &steps, &objective);
    if (!status.ok()) {
      log.add(ReasonCode::REQUEST_INVALID_DEFINITION, status.to_string());
      return conclude(PlanDecision::REJECTED_INVALID_REQUEST);
    }
    RecoveryPlan plan;
    plan.request = normalised.id;
    plan.coordinator_epoch = normalised.coordinator_epoch;
    plan.boot = normalised.boot;
    plan.attempt = normalised.attempt;
    plan.steps = std::move(steps);
    plan.objective = objective;
    plan.request_digest = result.request_digest;
    plan.definition_digest = definition.digest();
    plan.evidence_digest = normalised.evidence.digest();
    plan.authority_digest = normalised.authority.digest();
    plan.policy_digest = normalised.policy.digest();
    for (PlanStep& step : plan.steps) {
      const AuthorityBinding* binding = normalised.authority.find(step.required_domain);
      step.required_generation = binding != nullptr ? binding->granted : Generation{};
      step.issued_level = AuthorityLevel::RECOMMENDATION;
    }
    Explanation accepted;
    accepted.code = ReasonCode::PLAN_ACCEPTED;
    accepted.text = "plan satisfies every goal with zero safety violations";
    plan.explanations.push_back(accepted);
    Explanation optimal;
    optimal.code = ReasonCode::PLAN_OPTIMAL_BY_OBJECTIVE;
    optimal.text = "objective " + objective.to_string() +
                   " is minimal over the explored plan space (nodes expanded " +
                   std::to_string(outcome.nodes_expanded) + ")";
    plan.explanations.push_back(optimal);
    // The digest covers every field of the plan except the identity that is
    // derived from it, so it is computed once the plan is fully populated.
    plan.plan_digest = plan.compute_digest();
    plan.id = PlanId::from_value(plan.plan_digest.lo == 0 ? 1 : plan.plan_digest.lo);
    log.add(accepted);
    log.add(optimal);
    result.plan = std::move(plan);
    return conclude(PlanDecision::PLAN_FOUND);
  }

  if (outcome.budget_exhausted) {
    log.add(ReasonCode::SEARCH_BUDGET_EXHAUSTED,
            std::string("search budget reached after ") + std::to_string(outcome.nodes_expanded) +
                " expansions; no conclusion about feasibility is claimed");
    if (outcome.accounting_overflow) {
      log.add(ReasonCode::SEARCH_BUDGET_EXHAUSTED, "objective accounting overflowed 64 bits");
    }
    return conclude(PlanDecision::INDETERMINATE_SEARCH_LIMIT);
  }

  if (!unresolved_referenced.empty()) {
    log.add(ReasonCode::EVIDENCE_SUBJECT_MISSING,
            "the search space was exhausted but evidence does not establish every subject a "
            "step or goal depends on, so infeasibility cannot be claimed");
    return conclude(PlanDecision::INDETERMINATE_INCOMPLETE_EVIDENCE);
  }

  InfeasibilityCertificate certificate;
  certificate.kind = ProofKind::EXHAUSTIVE_SEARCH;
  certificate.request_digest = result.request_digest;
  certificate.policy_digest = normalised.policy.digest();
  certificate.nodes_expanded = outcome.nodes_expanded;
  certificate.nodes_generated = outcome.nodes_generated;
  certificate.reachable_states = outcome.reachable_states;
  certificate.assumptions.push_back(
      "the plan state space is finite: every action executes at most max_occurrences times");
  certificate.assumptions.push_back(
      "evidence establishes every subject referenced by a precondition or goal");
  certificate.assumptions.push_back(std::string("policy: irreversible actions ") +
                                    (normalised.policy.allow_irreversible_actions ? "allowed"
                                                                                  : "excluded") +
                                    ", plan length bounded by " +
                                    std::to_string(outcome.effective_step_bound) + " steps");
  if (outcome.step_bound_binding) {
    certificate.assumptions.push_back(
        "policy.max_plan_steps is smaller than the total occurrence bound, so the proof is "
        "relative to that bound");
  }
  Explanation explanation;
  explanation.code = ReasonCode::PROOF_EXHAUSTIVE_SEARCH;
  explanation.detail_a = outcome.nodes_expanded;
  explanation.detail_b = outcome.reachable_states;
  explanation.text = "the reachable plan-prefix space was exhausted without a solution";
  certificate.explanations.push_back(explanation);
  log.add(explanation);
  result.certificate = std::move(certificate);
  return conclude(PlanDecision::PROVEN_INFEASIBLE);
}

}  // namespace nrp
