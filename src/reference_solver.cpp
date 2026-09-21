// Network Recovery Planner - slow independent exact reference solver.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// The reference solver enumerates every action sequence inside its limits and
// re-simulates each one from scratch with its own checker. It performs no
// pruning, no dominance elimination and no incremental accounting, and it shares
// no code with the production planner or with validate.cpp. That is what makes
// it usable as a differential oracle rather than a second opinion from the same
// source.
#include "nrp/reference_solver.hpp"

#include <algorithm>
#include <functional>
#include <map>
#include <set>
#include <vector>

namespace nrp {
namespace {

struct RefState {
  std::vector<std::uint8_t> node_up;
  std::vector<std::uint8_t> link_up;
  std::vector<std::uint8_t> restored;
  std::vector<std::uint8_t> node_known;
  std::vector<std::uint8_t> link_known;
  std::vector<std::uint8_t> resource_known;
  std::vector<std::uint8_t> service_known;
  std::vector<std::uint32_t> available;
  std::vector<std::uint32_t> reachable;
  std::vector<std::uint32_t> occurrences;
};

struct Lookup {
  std::map<std::uint64_t, std::size_t> node;
  std::map<std::uint64_t, std::size_t> link;
  std::map<std::uint64_t, std::size_t> service;
  std::map<std::uint64_t, std::size_t> resource;
  std::map<std::uint64_t, std::size_t> action;
  std::map<std::uint64_t, std::size_t> group;

  void build(const FabricDefinition& definition) {
    for (std::size_t i = 0; i < definition.nodes.size(); ++i) node[definition.nodes[i].id.value()] = i;
    for (std::size_t i = 0; i < definition.links.size(); ++i) link[definition.links[i].id.value()] = i;
    for (std::size_t i = 0; i < definition.services.size(); ++i) {
      service[definition.services[i].id.value()] = i;
    }
    for (std::size_t i = 0; i < definition.resources.size(); ++i) {
      resource[definition.resources[i].id.value()] = i;
    }
    for (std::size_t i = 0; i < definition.actions.size(); ++i) {
      action[definition.actions[i].id.value()] = i;
    }
    for (std::size_t i = 0; i < definition.exclusion_groups.size(); ++i) {
      group[definition.exclusion_groups[i].id.value()] = i;
    }
  }

  std::size_t subject(const Subject& subject) const {
    const std::map<std::uint64_t, std::size_t>* table = nullptr;
    switch (subject.kind) {
      case SubjectKind::NODE: table = &node; break;
      case SubjectKind::LINK: table = &link; break;
      case SubjectKind::SERVICE: table = &service; break;
      case SubjectKind::RESOURCE: table = &resource; break;
      case SubjectKind::ACTION: table = &action; break;
      case SubjectKind::NONE:
      case SubjectKind::FABRIC:
        return static_cast<std::size_t>(-1);
    }
    const auto it = table->find(subject.id);
    return it == table->end() ? static_cast<std::size_t>(-1) : it->second;
  }
};

std::uint64_t ref_shortfall(const FabricDefinition& definition,
                            const RefState& state,
                            bool targets) {
  std::uint64_t total = 0;
  for (std::size_t index = 0; index < definition.services.size(); ++index) {
    const std::uint32_t reference = targets ? definition.services[index].target_reachable
                                            : definition.services[index].required_reachable;
    if (reference == 0) continue;
    if (state.service_known[index] == 0) {
      total += reference;
      continue;
    }
    if (state.reachable[index] < reference) total += reference - state.reachable[index];
  }
  return total;
}

AuthorityDomain ref_domain(EvidenceKind kind) {
  return kind == EvidenceKind::RESOURCE_AVAILABLE_UNITS || kind == EvidenceKind::RESOURCE_RESTORED
             ? AuthorityDomain::RESOURCE_LEASE
             : AuthorityDomain::FABRIC_STATE;
}

RefState ref_initial(const FabricDefinition& definition,
                     const Lookup& lookup,
                     const PlanRequest& request) {
  RefState state;
  state.node_up.assign(definition.nodes.size(), 0);
  state.link_up.assign(definition.links.size(), 0);
  state.restored.assign(definition.resources.size(), 0);
  state.node_known.assign(definition.nodes.size(), 0);
  state.link_known.assign(definition.links.size(), 0);
  state.resource_known.assign(definition.resources.size(), 0);
  state.service_known.assign(definition.services.size(), 0);
  state.available.assign(definition.resources.size(), 0);
  state.reachable.assign(definition.services.size(), 0);
  state.occurrences.assign(definition.actions.size(), 0);
  for (std::size_t index = 0; index < definition.resources.size(); ++index) {
    state.available[index] = definition.resources[index].capacity;
  }
  for (const EvidenceFact& fact : request.evidence.facts) {
    if (!is_valid(fact.kind)) continue;
    if (fact.subject.kind != expected_subject(fact.kind)) continue;
    if (fact.source_domain != ref_domain(fact.kind)) continue;
    if (fact.label != TrustLabel::REAL && fact.label != TrustLabel::SYNTHETIC) continue;
    const AuthorityBinding* binding = request.authority.find(fact.source_domain);
    if (binding == nullptr || fact.generation != binding->granted) continue;
    const std::size_t index = lookup.subject(fact.subject);
    if (index == static_cast<std::size_t>(-1)) continue;
    bool superseded = false;
    bool conflicting = false;
    for (const EvidenceFact& other : request.evidence.facts) {
      if (other.kind != fact.kind || other.subject != fact.subject) continue;
      if (other.sequence > fact.sequence) superseded = true;
      if (other.sequence == fact.sequence && other.value != fact.value) conflicting = true;
    }
    if (superseded || conflicting) continue;
    switch (fact.kind) {
      case EvidenceKind::LINK_OPERATIONAL:
        if (fact.value > 1) continue;
        state.link_up[index] = static_cast<std::uint8_t>(fact.value);
        state.link_known[index] = 1;
        break;
      case EvidenceKind::NODE_OPERATIONAL:
        if (fact.value > 1) continue;
        state.node_up[index] = static_cast<std::uint8_t>(fact.value);
        state.node_known[index] = 1;
        break;
      case EvidenceKind::SERVICE_REACHABLE_ENDPOINTS:
        if (fact.value > definition.services[index].max_reachable) continue;
        state.reachable[index] = static_cast<std::uint32_t>(fact.value);
        state.service_known[index] = 1;
        break;
      case EvidenceKind::RESOURCE_AVAILABLE_UNITS:
        if (fact.value > definition.resources[index].capacity) continue;
        state.available[index] = static_cast<std::uint32_t>(fact.value);
        state.resource_known[index] = 1;
        break;
      case EvidenceKind::RESOURCE_RESTORED:
        if (fact.value > 1) continue;
        state.restored[index] = static_cast<std::uint8_t>(fact.value);
        state.resource_known[index] = 1;
        break;
      case EvidenceKind::COUNT:
        break;
    }
  }
  return state;
}

bool ref_precondition(const Lookup& lookup,
                      const RefState& state,
                      const Precondition& precondition) {
  const std::size_t index = lookup.subject(precondition.subject);
  if (index == static_cast<std::size_t>(-1)) return false;
  switch (precondition.kind) {
    case PreconditionKind::LINK_OPERATIONAL:
      return state.link_known[index] != 0 && state.link_up[index] != 0;
    case PreconditionKind::LINK_NOT_OPERATIONAL:
      return state.link_known[index] != 0 && state.link_up[index] == 0;
    case PreconditionKind::NODE_OPERATIONAL:
      return state.node_known[index] != 0 && state.node_up[index] != 0;
    case PreconditionKind::NODE_NOT_OPERATIONAL:
      return state.node_known[index] != 0 && state.node_up[index] == 0;
    case PreconditionKind::SERVICE_REACHABLE_AT_LEAST:
      return state.service_known[index] != 0 && state.reachable[index] >= precondition.value;
    case PreconditionKind::SERVICE_REACHABLE_AT_MOST:
      return state.service_known[index] != 0 && state.reachable[index] <= precondition.value;
    case PreconditionKind::RESOURCE_AVAILABLE_AT_LEAST:
      return state.resource_known[index] != 0 && state.available[index] >= precondition.value;
    case PreconditionKind::ACTION_EXECUTED_AT_LEAST:
      return state.occurrences[index] >= precondition.value;
    case PreconditionKind::COUNT:
      return false;
  }
  return false;
}

struct RefEvaluation {
  bool valid = false;
  ObjectiveVector objective{};
};

/// Re-simulates one explicit sequence from scratch and computes both validity
/// and the full objective vector. Validity requires: every step admissible,
/// every precondition established, every authority binding current, no service
/// floor ever deepened, and every goal satisfied at the end.
RefEvaluation reference_evaluate(const PlanRequest& request,
                                 const std::vector<ActionId>& encoding) {
  RefEvaluation evaluation;
  PlanRequest normalised = request;
  normalised.definition.canonicalise();
  normalised.evidence.canonicalise();
  normalised.authority.canonicalise();
  const FabricDefinition& definition = normalised.definition;
  if (encoding.size() > normalised.policy.max_plan_steps) return evaluation;

  Lookup lookup;
  lookup.build(definition);
  RefState state = ref_initial(definition, lookup, normalised);
  if (normalised.policy.require_current_authority) {
    for (const ActionSpec& action : definition.actions) {
      const AuthorityBinding* binding = normalised.authority.find(action.required_domain);
      if (binding == nullptr || binding->evaluate() != BindingState::CURRENT) return evaluation;
      if (binding->level < action.required_level) return evaluation;
    }
  }

  std::vector<std::vector<std::pair<std::size_t, std::uint32_t>>> holds(
      definition.resources.size());
  std::uint64_t previous_floor = ref_shortfall(definition, state, false);
  std::uint64_t previous_completeness = ref_shortfall(definition, state, true);
  ObjectiveVector objective{};

  std::size_t position = 0;
  for (const ActionId& id : encoding) {
    const auto action_it = lookup.action.find(id.value());
    if (action_it == lookup.action.end()) return evaluation;
    const std::size_t action_index = action_it->second;
    const ActionSpec& action = definition.actions[action_index];
    if (state.occurrences[action_index] >= action.max_occurrences) return evaluation;
    for (const ActionDependency& dependency : action.dependencies) {
      const auto predecessor = lookup.action.find(dependency.predecessor.value());
      if (predecessor == lookup.action.end()) return evaluation;
      if (state.occurrences[predecessor->second] < dependency.min_occurrences) return evaluation;
    }
    if (state.occurrences[action_index] == 0) {
      for (const ExclusionGroupId& group : action.exclusion_groups) {
        const auto group_it = lookup.group.find(group.value());
        if (group_it == lookup.group.end()) return evaluation;
        std::uint32_t selected = 0;
        for (std::size_t candidate = 0; candidate < definition.actions.size(); ++candidate) {
          if (state.occurrences[candidate] == 0) continue;
          for (const ExclusionGroupId& other : definition.actions[candidate].exclusion_groups) {
            if (other == group) {
              ++selected;
              break;
            }
          }
        }
        if (selected >= definition.exclusion_groups[group_it->second].max_selected) {
          return evaluation;
        }
      }
    }
    for (const Precondition& precondition : action.preconditions) {
      if (!ref_precondition(lookup, state, precondition)) return evaluation;
    }
    if (action.reversibility == Reversibility::IRREVERSIBLE &&
        !normalised.policy.allow_irreversible_actions) {
      return evaluation;
    }

    for (const ResourceUse& use : action.resource_uses) {
      const auto resource_it = lookup.resource.find(use.resource.value());
      if (resource_it == lookup.resource.end()) return evaluation;
      const ResourceSpec& resource = definition.resources[resource_it->second];
      if (resource.kind == ResourceKind::CONSUMABLE) {
        if (state.resource_known[resource_it->second] == 0) return evaluation;
        if (state.available[resource_it->second] < use.units) return evaluation;
      } else {
        std::uint32_t overlapping = use.units;
        for (const auto& hold : holds[resource_it->second]) {
          const std::size_t distance = position - hold.first;
          if (distance < resource.hold_steps || (resource.hold_steps == 0 && distance == 0)) {
            overlapping += hold.second;
          }
        }
        if (overlapping > resource.capacity) return evaluation;
      }
    }

    for (const Effect& effect : action.effects) {
      const std::size_t index = lookup.subject(effect.subject);
      if (index == static_cast<std::size_t>(-1)) return evaluation;
      switch (effect.kind) {
        case EffectKind::SET_LINK_OPERATIONAL:
          state.link_up[index] = static_cast<std::uint8_t>(effect.value != 0 ? 1 : 0);
          state.link_known[index] = 1;
          break;
        case EffectKind::SET_NODE_OPERATIONAL:
          state.node_up[index] = static_cast<std::uint8_t>(effect.value != 0 ? 1 : 0);
          state.node_known[index] = 1;
          break;
        case EffectKind::SET_SERVICE_REACHABLE:
          if (effect.value < 0 ||
              static_cast<std::uint64_t>(effect.value) >
                  definition.services[index].max_reachable) {
            return evaluation;
          }
          state.reachable[index] = static_cast<std::uint32_t>(effect.value);
          state.service_known[index] = 1;
          break;
        case EffectKind::SERVICE_REACHABLE_DELTA: {
          if (state.service_known[index] == 0) {
            if (definition.services[index].required_reachable > 0) return evaluation;
            break;
          }
          const std::int64_t updated =
              static_cast<std::int64_t>(state.reachable[index]) + effect.value;
          if (updated < 0 ||
              static_cast<std::uint64_t>(updated) > definition.services[index].max_reachable) {
            return evaluation;
          }
          state.reachable[index] = static_cast<std::uint32_t>(updated);
          break;
        }
        case EffectKind::MARK_RESOURCE_RESTORED:
          state.restored[index] = 1;
          state.resource_known[index] = 1;
          break;
        case EffectKind::SET_RESOURCE_AVAILABLE:
          if (effect.value < 0 ||
              static_cast<std::uint64_t>(effect.value) > definition.resources[index].capacity) {
            return evaluation;
          }
          state.available[index] = static_cast<std::uint32_t>(effect.value);
          state.resource_known[index] = 1;
          break;
        case EffectKind::COUNT:
          return evaluation;
      }
    }
    for (const ResourceUse& use : action.resource_uses) {
      const auto resource_it = lookup.resource.find(use.resource.value());
      if (resource_it == lookup.resource.end()) return evaluation;
      if (definition.resources[resource_it->second].kind == ResourceKind::CONSUMABLE) {
        state.available[resource_it->second] -= use.units;
      } else {
        holds[resource_it->second].emplace_back(position, use.units);
      }
    }

    const std::uint64_t floor_after = ref_shortfall(definition, state, false);
    if (floor_after > previous_floor) {
      ++objective[0];
      objective[1] += floor_after - previous_floor;
      return evaluation;  // a step that deepens a floor makes the sequence invalid
    }
    previous_floor = floor_after;
    const std::uint64_t completeness_after = ref_shortfall(definition, state, true);
    if (completeness_after > previous_completeness) {
      objective[2] += completeness_after - previous_completeness;
    }
    previous_completeness = completeness_after;

    objective[3] += action.blast_radius;
    objective[4] += 1;
    objective[5] += action.disruption;
    objective[6] += action.cost_units;
    objective[7] += action.duration_ticks;
    state.occurrences[action_index] += 1;
    ++position;
  }

  for (const GoalSpec& goal : definition.goals) {
    const std::size_t index = lookup.subject(goal.subject);
    if (index == static_cast<std::size_t>(-1)) return evaluation;
    switch (goal.kind) {
      case GoalKind::LINK_OPERATIONAL:
        if (state.link_known[index] == 0 || state.link_up[index] == 0) return evaluation;
        break;
      case GoalKind::NODE_OPERATIONAL:
        if (state.node_known[index] == 0 || state.node_up[index] == 0) return evaluation;
        break;
      case GoalKind::RESOURCE_RESTORED:
        if (state.resource_known[index] == 0 || state.restored[index] == 0) return evaluation;
        break;
      case GoalKind::SERVICE_REACHABLE_AT_LEAST:
        if (state.service_known[index] == 0) return evaluation;
        if (state.reachable[index] < goal.value) return evaluation;
        break;
      case GoalKind::COUNT:
        return evaluation;
    }
  }
  evaluation.valid = true;
  evaluation.objective = objective;
  return evaluation;
}

}  // namespace

bool reference_check_sequence(const PlanRequest& request,
                              const std::vector<ActionId>& encoding) {
  return reference_evaluate(request, encoding).valid;
}

ReferenceOutcome reference_solve(const PlanRequest& request, const ReferenceLimits& limits) {
  ReferenceOutcome outcome;
  PlanRequest normalised = request;
  normalised.definition.canonicalise();
  normalised.evidence.canonicalise();
  normalised.authority.canonicalise();
  const FabricDefinition& definition = normalised.definition;

  if (normalised.policy.max_plan_steps == 0 || limits.max_plan_steps == 0) {
    outcome.kind = ReferenceOutcome::Kind::INVALID_INPUT;
    return outcome;
  }
  std::uint64_t occurrence_bound = 0;
  for (const ActionSpec& action : definition.actions) {
    if (add_overflow(occurrence_bound, action.max_occurrences, &occurrence_bound)) {
      occurrence_bound = UINT64_MAX;
      break;
    }
  }
  const std::uint64_t depth_bound =
      std::min({limits.max_plan_steps, normalised.policy.max_plan_steps, occurrence_bound});
  if (depth_bound > 12) {
    // The reference solver refuses to run where the enumeration is not obviously
    // tractable; it reports the limit instead of pretending to be exact.
    outcome.kind = ReferenceOutcome::Kind::LIMIT_REACHED;
    return outcome;
  }

  std::vector<ActionId> current;
  std::vector<std::uint32_t> counts(definition.actions.size(), 0);
  bool aborted = false;
  bool found = false;
  ObjectiveVector best{};
  std::vector<ActionId> best_encoding;

  const auto visit = [&]() {
    ++outcome.sequences_examined;
    const RefEvaluation evaluation = reference_evaluate(normalised, current);
    if (!evaluation.valid) return;
    ++outcome.valid_plans;
    if (!found) {
      found = true;
      best = evaluation.objective;
      best_encoding = current;
      return;
    }
    const int order = compare_objective(evaluation.objective, best);
    if (order < 0 || (order == 0 && compare_encoding(current, best_encoding) < 0)) {
      best = evaluation.objective;
      best_encoding = current;
    }
  };

  std::function<void()> descend = [&]() {
    if (aborted) return;
    visit();
    if (current.size() >= depth_bound) return;
    for (std::size_t index = 0; index < definition.actions.size(); ++index) {
      if (counts[index] >= definition.actions[index].max_occurrences) continue;
      if (outcome.sequences_examined >= limits.max_sequences) {
        aborted = true;
        return;
      }
      counts[index] += 1;
      current.push_back(definition.actions[index].id);
      descend();
      current.pop_back();
      counts[index] -= 1;
      if (aborted) return;
    }
  };
  descend();

  outcome.kind =
      aborted ? ReferenceOutcome::Kind::LIMIT_REACHED : ReferenceOutcome::Kind::COMPLETED;
  outcome.plan_found = found;
  outcome.objective = best;
  outcome.encoding = best_encoding;
  return outcome;
}

}  // namespace nrp
