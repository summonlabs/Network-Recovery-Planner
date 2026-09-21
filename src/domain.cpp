// Network Recovery Planner - fabric definition, state and request.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "nrp/domain.hpp"

#include <algorithm>
#include <set>

#include "nrp/codec.hpp"

namespace nrp {
namespace {

Status invalid(std::string text) {
  return Status::error(StatusCode::INVALID_ARGUMENT, std::move(text));
}

bool subject_exists(const FabricDefinition& definition, const Subject& subject) {
  switch (subject.kind) {
    case SubjectKind::NODE:
      return definition.node_index(NodeId::from_value(subject.id)) != static_cast<std::size_t>(-1);
    case SubjectKind::LINK:
      return definition.link_index(LinkId::from_value(subject.id)) != static_cast<std::size_t>(-1);
    case SubjectKind::SERVICE:
      return definition.service_index(ServiceId::from_value(subject.id)) != static_cast<std::size_t>(-1);
    case SubjectKind::RESOURCE:
      return definition.resource_index(ResourceId::from_value(subject.id)) != static_cast<std::size_t>(-1);
    case SubjectKind::ACTION:
      return definition.action_index(ActionId::from_value(subject.id)) != static_cast<std::size_t>(-1);
    case SubjectKind::FABRIC:
    case SubjectKind::NONE:
      return false;
  }
  return false;
}

}  // namespace

const ModelLimits& default_model_limits() noexcept {
  static const ModelLimits limits;
  return limits;
}

const char* to_string(ResourceKind kind) noexcept {
  switch (kind) {
    case ResourceKind::CONSUMABLE: return "CONSUMABLE";
    case ResourceKind::REUSABLE: return "REUSABLE";
    case ResourceKind::COUNT: return "COUNT";
  }
  return "UNRECOGNISED_RESOURCE_KIND";
}

bool is_valid(ResourceKind kind) noexcept {
  switch (kind) {
    case ResourceKind::CONSUMABLE:
    case ResourceKind::REUSABLE:
      return true;
    case ResourceKind::COUNT:
      return false;
  }
  return false;
}

const char* to_string(PreconditionKind kind) noexcept {
  switch (kind) {
    case PreconditionKind::LINK_OPERATIONAL: return "LINK_OPERATIONAL";
    case PreconditionKind::LINK_NOT_OPERATIONAL: return "LINK_NOT_OPERATIONAL";
    case PreconditionKind::NODE_OPERATIONAL: return "NODE_OPERATIONAL";
    case PreconditionKind::NODE_NOT_OPERATIONAL: return "NODE_NOT_OPERATIONAL";
    case PreconditionKind::SERVICE_REACHABLE_AT_LEAST: return "SERVICE_REACHABLE_AT_LEAST";
    case PreconditionKind::SERVICE_REACHABLE_AT_MOST: return "SERVICE_REACHABLE_AT_MOST";
    case PreconditionKind::RESOURCE_AVAILABLE_AT_LEAST: return "RESOURCE_AVAILABLE_AT_LEAST";
    case PreconditionKind::ACTION_EXECUTED_AT_LEAST: return "ACTION_EXECUTED_AT_LEAST";
    case PreconditionKind::COUNT: return "COUNT";
  }
  return "UNRECOGNISED_PRECONDITION_KIND";
}

bool is_valid(PreconditionKind kind) noexcept {
  switch (kind) {
    case PreconditionKind::LINK_OPERATIONAL:
    case PreconditionKind::LINK_NOT_OPERATIONAL:
    case PreconditionKind::NODE_OPERATIONAL:
    case PreconditionKind::NODE_NOT_OPERATIONAL:
    case PreconditionKind::SERVICE_REACHABLE_AT_LEAST:
    case PreconditionKind::SERVICE_REACHABLE_AT_MOST:
    case PreconditionKind::RESOURCE_AVAILABLE_AT_LEAST:
    case PreconditionKind::ACTION_EXECUTED_AT_LEAST:
      return true;
    case PreconditionKind::COUNT:
      return false;
  }
  return false;
}

SubjectKind expected_subject(PreconditionKind kind) noexcept {
  switch (kind) {
    case PreconditionKind::LINK_OPERATIONAL:
    case PreconditionKind::LINK_NOT_OPERATIONAL:
      return SubjectKind::LINK;
    case PreconditionKind::NODE_OPERATIONAL:
    case PreconditionKind::NODE_NOT_OPERATIONAL:
      return SubjectKind::NODE;
    case PreconditionKind::SERVICE_REACHABLE_AT_LEAST:
    case PreconditionKind::SERVICE_REACHABLE_AT_MOST:
      return SubjectKind::SERVICE;
    case PreconditionKind::RESOURCE_AVAILABLE_AT_LEAST:
      return SubjectKind::RESOURCE;
    case PreconditionKind::ACTION_EXECUTED_AT_LEAST:
      return SubjectKind::ACTION;
    case PreconditionKind::COUNT:
      return SubjectKind::NONE;
  }
  return SubjectKind::NONE;
}

const char* to_string(EffectKind kind) noexcept {
  switch (kind) {
    case EffectKind::SET_LINK_OPERATIONAL: return "SET_LINK_OPERATIONAL";
    case EffectKind::SET_NODE_OPERATIONAL: return "SET_NODE_OPERATIONAL";
    case EffectKind::SERVICE_REACHABLE_DELTA: return "SERVICE_REACHABLE_DELTA";
    case EffectKind::MARK_RESOURCE_RESTORED: return "MARK_RESOURCE_RESTORED";
    case EffectKind::SET_SERVICE_REACHABLE: return "SET_SERVICE_REACHABLE";
    case EffectKind::SET_RESOURCE_AVAILABLE: return "SET_RESOURCE_AVAILABLE";
    case EffectKind::COUNT: return "COUNT";
  }
  return "UNRECOGNISED_EFFECT_KIND";
}

bool is_valid(EffectKind kind) noexcept {
  switch (kind) {
    case EffectKind::SET_LINK_OPERATIONAL:
    case EffectKind::SET_NODE_OPERATIONAL:
    case EffectKind::SERVICE_REACHABLE_DELTA:
    case EffectKind::MARK_RESOURCE_RESTORED:
    case EffectKind::SET_SERVICE_REACHABLE:
    case EffectKind::SET_RESOURCE_AVAILABLE:
      return true;
    case EffectKind::COUNT:
      return false;
  }
  return false;
}

SubjectKind expected_subject(EffectKind kind) noexcept {
  switch (kind) {
    case EffectKind::SET_LINK_OPERATIONAL: return SubjectKind::LINK;
    case EffectKind::SET_NODE_OPERATIONAL: return SubjectKind::NODE;
    case EffectKind::SERVICE_REACHABLE_DELTA: return SubjectKind::SERVICE;
    case EffectKind::SET_SERVICE_REACHABLE: return SubjectKind::SERVICE;
    case EffectKind::MARK_RESOURCE_RESTORED: return SubjectKind::RESOURCE;
    case EffectKind::SET_RESOURCE_AVAILABLE: return SubjectKind::RESOURCE;
    case EffectKind::COUNT: return SubjectKind::NONE;
  }
  return SubjectKind::NONE;
}

const char* to_string(ActionKind kind) noexcept {
  switch (kind) {
    case ActionKind::REROUTE: return "REROUTE";
    case ActionKind::REPLACE: return "REPLACE";
    case ActionKind::RESTART: return "RESTART";
    case ActionKind::DRAIN: return "DRAIN";
    case ActionKind::ISOLATE: return "ISOLATE";
    case ActionKind::RESTORE: return "RESTORE";
    case ActionKind::DEGRADE: return "DEGRADE";
    case ActionKind::COUNT: return "COUNT";
  }
  return "UNRECOGNISED_ACTION_KIND";
}

bool is_valid(ActionKind kind) noexcept {
  switch (kind) {
    case ActionKind::REROUTE:
    case ActionKind::REPLACE:
    case ActionKind::RESTART:
    case ActionKind::DRAIN:
    case ActionKind::ISOLATE:
    case ActionKind::RESTORE:
    case ActionKind::DEGRADE:
      return true;
    case ActionKind::COUNT:
      return false;
  }
  return false;
}

const char* to_string(Reversibility value) noexcept {
  switch (value) {
    case Reversibility::REVERSIBLE: return "REVERSIBLE";
    case Reversibility::IRREVERSIBLE: return "IRREVERSIBLE";
    case Reversibility::COUNT: return "COUNT";
  }
  return "UNRECOGNISED_REVERSIBILITY";
}

bool is_valid(Reversibility value) noexcept {
  switch (value) {
    case Reversibility::REVERSIBLE:
    case Reversibility::IRREVERSIBLE:
      return true;
    case Reversibility::COUNT:
      return false;
  }
  return false;
}

const char* to_string(GoalKind kind) noexcept {
  switch (kind) {
    case GoalKind::SERVICE_REACHABLE_AT_LEAST: return "SERVICE_REACHABLE_AT_LEAST";
    case GoalKind::LINK_OPERATIONAL: return "LINK_OPERATIONAL";
    case GoalKind::NODE_OPERATIONAL: return "NODE_OPERATIONAL";
    case GoalKind::RESOURCE_RESTORED: return "RESOURCE_RESTORED";
    case GoalKind::COUNT: return "COUNT";
  }
  return "UNRECOGNISED_GOAL_KIND";
}

bool is_valid(GoalKind kind) noexcept {
  switch (kind) {
    case GoalKind::SERVICE_REACHABLE_AT_LEAST:
    case GoalKind::LINK_OPERATIONAL:
    case GoalKind::NODE_OPERATIONAL:
    case GoalKind::RESOURCE_RESTORED:
      return true;
    case GoalKind::COUNT:
      return false;
  }
  return false;
}

SubjectKind expected_subject(GoalKind kind) noexcept {
  switch (kind) {
    case GoalKind::SERVICE_REACHABLE_AT_LEAST: return SubjectKind::SERVICE;
    case GoalKind::LINK_OPERATIONAL: return SubjectKind::LINK;
    case GoalKind::NODE_OPERATIONAL: return SubjectKind::NODE;
    case GoalKind::RESOURCE_RESTORED: return SubjectKind::RESOURCE;
    case GoalKind::COUNT: return SubjectKind::NONE;
  }
  return SubjectKind::NONE;
}

void FabricDefinition::canonicalise() {
  std::sort(nodes.begin(), nodes.end());
  std::sort(links.begin(), links.end());
  std::sort(services.begin(), services.end());
  std::sort(resources.begin(), resources.end());
  // Actions are ordered by identity; every nested list has a canonical order so
  // two definitions that differ only by insertion order encode identically.
  std::sort(actions.begin(), actions.end(),
            [](const ActionSpec& a, const ActionSpec& b) { return a.id < b.id; });
  for (ActionSpec& action : actions) {
    std::sort(action.preconditions.begin(), action.preconditions.end());
    std::sort(action.effects.begin(), action.effects.end());
    std::sort(action.resource_uses.begin(), action.resource_uses.end());
    std::sort(action.dependencies.begin(), action.dependencies.end());
    std::sort(action.exclusion_groups.begin(), action.exclusion_groups.end());
  }
  std::sort(exclusion_groups.begin(), exclusion_groups.end());
  std::sort(goals.begin(), goals.end(), [](const GoalSpec& a, const GoalSpec& b) {
    if (a.subject != b.subject) return a.subject < b.subject;
    if (a.kind != b.kind) return static_cast<std::uint8_t>(a.kind) < static_cast<std::uint8_t>(b.kind);
    if (a.value != b.value) return a.value < b.value;
    return a.weight < b.weight;
  });
}

std::size_t FabricDefinition::node_index(NodeId id) const noexcept {
  for (std::size_t index = 0; index < nodes.size(); ++index) {
    if (nodes[index].id == id) return index;
  }
  return static_cast<std::size_t>(-1);
}

std::size_t FabricDefinition::link_index(LinkId id) const noexcept {
  for (std::size_t index = 0; index < links.size(); ++index) {
    if (links[index].id == id) return index;
  }
  return static_cast<std::size_t>(-1);
}

std::size_t FabricDefinition::service_index(ServiceId id) const noexcept {
  for (std::size_t index = 0; index < services.size(); ++index) {
    if (services[index].id == id) return index;
  }
  return static_cast<std::size_t>(-1);
}

std::size_t FabricDefinition::resource_index(ResourceId id) const noexcept {
  for (std::size_t index = 0; index < resources.size(); ++index) {
    if (resources[index].id == id) return index;
  }
  return static_cast<std::size_t>(-1);
}

std::size_t FabricDefinition::action_index(ActionId id) const noexcept {
  for (std::size_t index = 0; index < actions.size(); ++index) {
    if (actions[index].id == id) return index;
  }
  return static_cast<std::size_t>(-1);
}

const ActionSpec* FabricDefinition::find_action(ActionId id) const noexcept {
  const std::size_t index = action_index(id);
  return index == static_cast<std::size_t>(-1) ? nullptr : &actions[index];
}

const ResourceSpec* FabricDefinition::find_resource(ResourceId id) const noexcept {
  const std::size_t index = resource_index(id);
  return index == static_cast<std::size_t>(-1) ? nullptr : &resources[index];
}

const ServiceSpec* FabricDefinition::find_service(ServiceId id) const noexcept {
  const std::size_t index = service_index(id);
  return index == static_cast<std::size_t>(-1) ? nullptr : &services[index];
}

void FabricDefinition::encode(CanonicalWriter& writer) const {
  writer.u32(static_cast<std::uint32_t>(nodes.size()));
  for (const NodeSpec& node : nodes) {
    writer.u64(node.id.value());
    writer.boolean(node.protected_node);
  }
  writer.u32(static_cast<std::uint32_t>(links.size()));
  for (const LinkSpec& link : links) {
    writer.u64(link.id.value());
    writer.u64(link.endpoint_a.value());
    writer.u64(link.endpoint_b.value());
  }
  writer.u32(static_cast<std::uint32_t>(services.size()));
  for (const ServiceSpec& service : services) {
    writer.u64(service.id.value());
    writer.u32(service.required_reachable);
    writer.u32(service.target_reachable);
    writer.u32(service.max_reachable);
    writer.boolean(service.protected_service);
  }
  writer.u32(static_cast<std::uint32_t>(resources.size()));
  for (const ResourceSpec& resource : resources) {
    writer.u64(resource.id.value());
    writer.u8(static_cast<std::uint8_t>(resource.kind));
    writer.u32(resource.capacity);
    writer.u32(resource.hold_steps);
  }
  writer.u32(static_cast<std::uint32_t>(actions.size()));
  for (const ActionSpec& action : actions) {
    writer.u64(action.id.value());
    writer.str(action.name);
    writer.u8(static_cast<std::uint8_t>(action.kind));
    writer.u8(static_cast<std::uint8_t>(action.reversibility));
    writer.u64(action.compensation.value());
    writer.u32(action.blast_radius);
    writer.u32(action.disruption);
    writer.u64(action.cost_units);
    writer.u64(action.duration_ticks);
    writer.u32(action.max_occurrences);
    writer.u8(static_cast<std::uint8_t>(action.required_domain));
    writer.u8(static_cast<std::uint8_t>(action.required_level));
    writer.u32(static_cast<std::uint32_t>(action.preconditions.size()));
    for (const Precondition& precondition : action.preconditions) {
      writer.u8(static_cast<std::uint8_t>(precondition.kind));
      writer.u8(static_cast<std::uint8_t>(precondition.subject.kind));
      writer.u64(precondition.subject.id);
      writer.u64(precondition.value);
    }
    writer.u32(static_cast<std::uint32_t>(action.effects.size()));
    for (const Effect& effect : action.effects) {
      writer.u8(static_cast<std::uint8_t>(effect.kind));
      writer.u8(static_cast<std::uint8_t>(effect.subject.kind));
      writer.u64(effect.subject.id);
      writer.i64(effect.value);
    }
    writer.u32(static_cast<std::uint32_t>(action.resource_uses.size()));
    for (const ResourceUse& use : action.resource_uses) {
      writer.u64(use.resource.value());
      writer.u32(use.units);
    }
    writer.u32(static_cast<std::uint32_t>(action.dependencies.size()));
    for (const ActionDependency& dependency : action.dependencies) {
      writer.u64(dependency.predecessor.value());
      writer.u32(dependency.min_occurrences);
    }
    writer.u32(static_cast<std::uint32_t>(action.exclusion_groups.size()));
    for (const ExclusionGroupId& group : action.exclusion_groups) {
      writer.u64(group.value());
    }
  }
  writer.u32(static_cast<std::uint32_t>(goals.size()));
  for (const GoalSpec& goal : goals) {
    writer.u8(static_cast<std::uint8_t>(goal.kind));
    writer.u8(static_cast<std::uint8_t>(goal.subject.kind));
    writer.u64(goal.subject.id);
    writer.u64(goal.value);
    writer.u32(goal.weight);
  }
  writer.u32(static_cast<std::uint32_t>(exclusion_groups.size()));
  for (const ExclusionGroup& group : exclusion_groups) {
    writer.u64(group.id.value());
    writer.u32(group.max_selected);
  }
}

Digest FabricDefinition::digest() const {
  CanonicalWriter writer;
  encode(writer);
  return digest_of(writer.buffer());
}

void FabricState::encode(CanonicalWriter& writer) const {
  writer.u32(static_cast<std::uint32_t>(node_operational.size()));
  for (std::uint8_t value : node_operational) writer.u8(value);
  writer.u32(static_cast<std::uint32_t>(link_operational.size()));
  for (std::uint8_t value : link_operational) writer.u8(value);
  writer.u32(static_cast<std::uint32_t>(resource_restored.size()));
  for (std::uint8_t value : resource_restored) writer.u8(value);
  writer.u32(static_cast<std::uint32_t>(resource_available.size()));
  for (std::uint32_t value : resource_available) writer.u32(value);
  writer.u32(static_cast<std::uint32_t>(service_reachable.size()));
  for (std::uint32_t value : service_reachable) writer.u32(value);
  writer.u32(static_cast<std::uint32_t>(action_occurrences.size()));
  for (std::uint32_t value : action_occurrences) writer.u32(value);
  writer.u32(static_cast<std::uint32_t>(node_known.size()));
  for (std::uint8_t value : node_known) writer.u8(value);
  writer.u32(static_cast<std::uint32_t>(link_known.size()));
  for (std::uint8_t value : link_known) writer.u8(value);
  writer.u32(static_cast<std::uint32_t>(resource_known.size()));
  for (std::uint8_t value : resource_known) writer.u8(value);
  writer.u32(static_cast<std::uint32_t>(service_known.size()));
  for (std::uint8_t value : service_known) writer.u8(value);
  writer.u64(tick);
}

void PlanPolicy::encode(CanonicalWriter& writer) const {
  writer.boolean(allow_irreversible_actions);
  writer.boolean(require_current_authority);
  writer.u64(max_plan_steps);
  writer.u64(max_nodes_expanded);
  writer.u64(max_generated_states);
  writer.u64(max_frontier_entries);
  writer.u32(budget_scale);
}

Digest PlanPolicy::digest() const {
  CanonicalWriter writer;
  encode(writer);
  return digest_of(writer.buffer());
}

void PlanRequest::encode(CanonicalWriter& writer) const {
  writer.u64(id.value());
  writer.u64(coordinator_epoch.value());
  writer.u64(boot.value());
  writer.u64(attempt.value());
  definition.encode(writer);
  evidence.encode(writer);
  authority.encode(writer);
  policy.encode(writer);
  writer.u32(static_cast<std::uint32_t>(fences.size()));
  for (const Fence& fence : fences) {
    encode_fence(fence, writer);
  }
}

Digest PlanRequest::digest() const {
  CanonicalWriter writer;
  encode(writer);
  return digest_of(writer.buffer());
}

// ---------------------------------------------------------------------------
// Definition validation
// ---------------------------------------------------------------------------

Status validate_definition(const FabricDefinition& definition,
                           const ModelLimits& limits,
                           ExplanationLog* log) {
  auto fail = [&](std::string text) {
    if (log != nullptr) log->add(ReasonCode::REQUEST_INVALID_DEFINITION, text);
    return invalid(std::move(text));
  };

  if (definition.nodes.size() > limits.max_nodes) return fail("node count exceeds the model limit");
  if (definition.links.size() > limits.max_links) return fail("link count exceeds the model limit");
  if (definition.services.size() > limits.max_services) {
    return fail("service count exceeds the model limit");
  }
  if (definition.resources.size() > limits.max_resources) {
    return fail("resource count exceeds the model limit");
  }
  if (definition.actions.size() > limits.max_actions) return fail("action count exceeds the model limit");
  if (definition.goals.size() > limits.max_goals) return fail("goal count exceeds the model limit");
  if (definition.exclusion_groups.size() > limits.max_exclusion_groups) {
    return fail("exclusion group count exceeds the model limit");
  }

  {
    std::set<std::uint64_t> seen;
    for (const NodeSpec& node : definition.nodes) {
      if (node.id.is_zero()) return fail("node identity must be non-zero");
      if (!seen.insert(node.id.value()).second) return fail("duplicate node identity");
    }
  }
  {
    std::set<std::uint64_t> seen;
    for (const LinkSpec& link : definition.links) {
      if (link.id.is_zero()) return fail("link identity must be non-zero");
      if (!seen.insert(link.id.value()).second) return fail("duplicate link identity");
      if (definition.node_index(link.endpoint_a) == static_cast<std::size_t>(-1)) {
        return fail("link references an unknown endpoint node");
      }
      if (definition.node_index(link.endpoint_b) == static_cast<std::size_t>(-1)) {
        return fail("link references an unknown endpoint node");
      }
    }
  }
  {
    std::set<std::uint64_t> seen;
    for (const ServiceSpec& service : definition.services) {
      if (service.id.is_zero()) return fail("service identity must be non-zero");
      if (!seen.insert(service.id.value()).second) return fail("duplicate service identity");
      if (service.max_reachable > limits.max_service_endpoints) {
        return fail("service max_reachable exceeds the model limit");
      }
      if (service.required_reachable > service.max_reachable) {
        return fail("service required_reachable exceeds max_reachable");
      }
      if (service.target_reachable > service.max_reachable) {
        return fail("service target_reachable exceeds max_reachable");
      }
      if (service.target_reachable < service.required_reachable) {
        return fail("service target_reachable is below required_reachable");
      }
    }
  }
  {
    std::set<std::uint64_t> seen;
    for (const ResourceSpec& resource : definition.resources) {
      if (resource.id.is_zero()) return fail("resource identity must be non-zero");
      if (!seen.insert(resource.id.value()).second) return fail("duplicate resource identity");
      if (!is_valid(resource.kind)) return fail("resource kind is outside the defined domain");
      if (resource.hold_steps > limits.max_hold_steps) {
        return fail("resource hold_steps exceeds the model limit");
      }
      if (resource.kind == ResourceKind::REUSABLE && resource.hold_steps == 0 &&
          resource.capacity > 0) {
        // hold_steps == 0 means the hold covers only the executing step, which is
        // well defined; nothing to reject here.
      }
    }
  }
  {
    std::set<std::uint64_t> seen;
    for (const ExclusionGroup& group : definition.exclusion_groups) {
      if (group.id.is_zero()) return fail("exclusion group identity must be non-zero");
      if (!seen.insert(group.id.value()).second) return fail("duplicate exclusion group identity");
      if (group.max_selected == 0) return fail("exclusion group max_selected must be at least one");
    }
  }
  {
    std::set<std::uint64_t> seen;
    for (const ActionSpec& action : definition.actions) {
      if (action.id.is_zero()) return fail("action identity must be non-zero");
      if (!seen.insert(action.id.value()).second) return fail("duplicate action identity");
      if (action.name.size() > limits.max_string_length) return fail("action name exceeds the limit");
      if (!is_valid(action.kind)) return fail("action kind is outside the defined domain");
      if (!is_valid(action.reversibility)) return fail("action reversibility is outside the domain");
      if (!is_valid(action.required_domain)) return fail("action required_domain is outside the domain");
      if (!is_valid(action.required_level)) return fail("action required_level is outside the domain");
      if (action.max_occurrences == 0) return fail("action max_occurrences must be at least one");
      if (action.max_occurrences > limits.max_action_occurrences) {
        return fail("action max_occurrences exceeds the model limit");
      }
      if (action.preconditions.size() > limits.max_preconditions_per_action) {
        return fail("action precondition count exceeds the model limit");
      }
      if (action.effects.size() > limits.max_effects_per_action) {
        return fail("action effect count exceeds the model limit");
      }
      if (action.reversibility == Reversibility::REVERSIBLE) {
        if (action.compensation.is_zero()) {
          return fail("reversible action must declare a compensation action");
        }
        if (action.compensation == action.id) {
          return fail("action cannot compensate itself");
        }
        if (definition.action_index(action.compensation) == static_cast<std::size_t>(-1)) {
          return fail("action compensation references an unknown action");
        }
      } else if (!action.compensation.is_zero()) {
        return fail("irreversible action must not declare a compensation action");
      }
      for (const Precondition& precondition : action.preconditions) {
        if (!is_valid(precondition.kind)) return fail("precondition kind is outside the domain");
        if (precondition.subject.kind != expected_subject(precondition.kind)) {
          return fail("precondition subject kind does not match the precondition kind");
        }
        if (!subject_exists(definition, precondition.subject)) {
          return fail("precondition references an unknown subject");
        }
      }
      for (const Effect& effect : action.effects) {
        if (!is_valid(effect.kind)) return fail("effect kind is outside the domain");
        if (effect.subject.kind != expected_subject(effect.kind)) {
          return fail("effect subject kind does not match the effect kind");
        }
        if (!subject_exists(definition, effect.subject)) {
          return fail("effect references an unknown subject");
        }
        if (effect.kind == EffectKind::SET_LINK_OPERATIONAL ||
            effect.kind == EffectKind::SET_NODE_OPERATIONAL) {
          if (effect.value != 0 && effect.value != 1) {
            return fail("SET effect value must be zero or one");
          }
        }
        if (effect.kind == EffectKind::MARK_RESOURCE_RESTORED && effect.value != 1) {
          return fail("MARK_RESOURCE_RESTORED value must be one");
        }
        if (effect.kind == EffectKind::SET_SERVICE_REACHABLE) {
          const ServiceSpec* service = definition.find_service(ServiceId::from_value(effect.subject.id));
          if (effect.value < 0) return fail("SET_SERVICE_REACHABLE value must not be negative");
          if (service != nullptr &&
              static_cast<std::uint64_t>(effect.value) > service->max_reachable) {
            return fail("SET_SERVICE_REACHABLE exceeds the structural maximum of the service");
          }
        }
        if (effect.kind == EffectKind::SET_RESOURCE_AVAILABLE) {
          const ResourceSpec* resource = definition.find_resource(ResourceId::from_value(effect.subject.id));
          if (effect.value < 0) return fail("SET_RESOURCE_AVAILABLE value must not be negative");
          if (resource != nullptr &&
              static_cast<std::uint64_t>(effect.value) > resource->capacity) {
            return fail("SET_RESOURCE_AVAILABLE exceeds the capacity of the resource");
          }
        }
      }
      for (const ResourceUse& use : action.resource_uses) {
        const ResourceSpec* resource = definition.find_resource(use.resource);
        if (resource == nullptr) return fail("resource use references an unknown resource");
        if (use.units == 0) return fail("resource use must request at least one unit");
        if (use.units > resource->capacity) {
          return fail("resource use exceeds the capacity of the resource");
        }
      }
      for (const ActionDependency& dependency : action.dependencies) {
        if (dependency.predecessor == action.id) {
          return fail("action dependency cycle: an action cannot require itself");
        }
        const ActionSpec* predecessor = definition.find_action(dependency.predecessor);
        if (predecessor == nullptr) return fail("action dependency references an unknown action");
        if (dependency.min_occurrences == 0) {
          return fail("action dependency min_occurrences must be at least one");
        }
        if (dependency.min_occurrences > predecessor->max_occurrences) {
          return fail("action dependency requires more occurrences than the action can execute");
        }
      }
      std::set<std::uint64_t> groups;
      for (const ExclusionGroupId& group : action.exclusion_groups) {
        if (group.is_zero()) return fail("exclusion group reference must be non-zero");
        if (!groups.insert(group.value()).second) {
          return fail("action lists the same exclusion group twice");
        }
        bool found = false;
        for (const ExclusionGroup& declared : definition.exclusion_groups) {
          if (declared.id == group) {
            found = true;
            break;
          }
        }
        if (!found) return fail("action references an unknown exclusion group");
      }
    }
  }
  for (const GoalSpec& goal : definition.goals) {
    if (!is_valid(goal.kind)) return fail("goal kind is outside the domain");
    if (goal.subject.kind != expected_subject(goal.kind)) {
      return fail("goal subject kind does not match the goal kind");
    }
    if (!subject_exists(definition, goal.subject)) return fail("goal references an unknown subject");
    if (goal.weight == 0) return fail("goal weight must be at least one");
    if (goal.kind == GoalKind::SERVICE_REACHABLE_AT_LEAST) {
      const ServiceSpec* service = definition.find_service(ServiceId::from_value(goal.subject.id));
      if (service != nullptr && goal.value > service->max_reachable) {
        return fail("service goal exceeds the structural maximum for the service");
      }
    }
  }
  return Status::success();
}

}  // namespace nrp
