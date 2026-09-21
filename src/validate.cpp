// Network Recovery Planner - independent plan validation.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// This translation unit deliberately re-implements state evolution, evidence
// reconciliation, resource accounting and objective accounting from scratch. It
// shares no simulation code with the planner, so agreement between the two is
// evidence rather than tautology.
#include "nrp/validate.hpp"

#include <algorithm>
#include <map>
#include <set>
#include <sstream>
#include <vector>

namespace nrp {
namespace {

constexpr std::uint32_t kPlanLevel = UINT32_MAX;

struct Violation {
  ReasonCode code = ReasonCode::NONE;
  std::uint32_t step = kPlanLevel;
  Subject subject{};
  std::string text;
};

class Report {
 public:
  void add(ReasonCode code, std::uint32_t step, Subject subject, std::string text) {
    ValidationFinding finding;
    finding.code = code;
    finding.step_index = step;
    finding.subject = subject;
    finding.text = std::move(text);
    report_.findings.push_back(std::move(finding));
  }
  ValidationReport& report() { return report_; }

 private:
  ValidationReport report_;
};

struct Tables {
  std::map<std::uint64_t, std::size_t> nodes;
  std::map<std::uint64_t, std::size_t> links;
  std::map<std::uint64_t, std::size_t> services;
  std::map<std::uint64_t, std::size_t> resources;
  std::map<std::uint64_t, std::size_t> actions;
  std::map<std::uint64_t, std::size_t> groups;

  void build(const FabricDefinition& definition) {
    for (std::size_t index = 0; index < definition.nodes.size(); ++index) {
      nodes.emplace(definition.nodes[index].id.value(), index);
    }
    for (std::size_t index = 0; index < definition.links.size(); ++index) {
      links.emplace(definition.links[index].id.value(), index);
    }
    for (std::size_t index = 0; index < definition.services.size(); ++index) {
      services.emplace(definition.services[index].id.value(), index);
    }
    for (std::size_t index = 0; index < definition.resources.size(); ++index) {
      resources.emplace(definition.resources[index].id.value(), index);
    }
    for (std::size_t index = 0; index < definition.actions.size(); ++index) {
      actions.emplace(definition.actions[index].id.value(), index);
    }
    for (std::size_t index = 0; index < definition.exclusion_groups.size(); ++index) {
      groups.emplace(definition.exclusion_groups[index].id.value(), index);
    }
  }

  std::size_t subject(const Subject& subject) const {
    switch (subject.kind) {
      case SubjectKind::NODE: {
        const auto it = nodes.find(subject.id);
        return it == nodes.end() ? static_cast<std::size_t>(-1) : it->second;
      }
      case SubjectKind::LINK: {
        const auto it = links.find(subject.id);
        return it == links.end() ? static_cast<std::size_t>(-1) : it->second;
      }
      case SubjectKind::SERVICE: {
        const auto it = services.find(subject.id);
        return it == services.end() ? static_cast<std::size_t>(-1) : it->second;
      }
      case SubjectKind::RESOURCE: {
        const auto it = resources.find(subject.id);
        return it == resources.end() ? static_cast<std::size_t>(-1) : it->second;
      }
      case SubjectKind::ACTION: {
        const auto it = actions.find(subject.id);
        return it == actions.end() ? static_cast<std::size_t>(-1) : it->second;
      }
      case SubjectKind::NONE:
      case SubjectKind::FABRIC:
        return static_cast<std::size_t>(-1);
    }
    return static_cast<std::size_t>(-1);
  }
};

struct State {
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
  std::uint64_t tick = 0;
};

struct FactView {
  std::vector<std::uint64_t> values;
  bool usable = false;
  Generation generation{};
  Sequence sequence{};
  SubjectState state = SubjectState::MISSING;
};

std::uint64_t shortfall(const FabricDefinition& definition, const State& state, bool targets) {
  std::uint64_t total = 0;
  for (std::size_t index = 0; index < definition.services.size(); ++index) {
    const ServiceSpec& service = definition.services[index];
    const std::uint32_t reference =
        targets ? service.target_reachable : service.required_reachable;
    if (reference == 0) continue;
    if (state.service_known[index] == 0) {
      total += reference;
      continue;
    }
    if (state.reachable[index] < reference) total += reference - state.reachable[index];
  }
  return total;
}

AuthorityDomain domain_of(EvidenceKind kind) {
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

EvidenceKind kind_of(PreconditionKind kind) {
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

bool value_admissible(const FabricDefinition& definition,
                      const Tables& tables,
                      const EvidenceFact& fact) {
  switch (fact.kind) {
    case EvidenceKind::LINK_OPERATIONAL: {
      const auto it = tables.links.find(fact.subject.id);
      return it != tables.links.end() && fact.value <= 1;
    }
    case EvidenceKind::NODE_OPERATIONAL: {
      const auto it = tables.nodes.find(fact.subject.id);
      return it != tables.nodes.end() && fact.value <= 1;
    }
    case EvidenceKind::SERVICE_REACHABLE_ENDPOINTS: {
      const auto it = tables.services.find(fact.subject.id);
      return it != tables.services.end() &&
             fact.value <= definition.services[it->second].max_reachable;
    }
    case EvidenceKind::RESOURCE_AVAILABLE_UNITS: {
      const auto it = tables.resources.find(fact.subject.id);
      return it != tables.resources.end() &&
             fact.value <= definition.resources[it->second].capacity;
    }
    case EvidenceKind::RESOURCE_RESTORED: {
      const auto it = tables.resources.find(fact.subject.id);
      return it != tables.resources.end() && fact.value <= 1;
    }
    case EvidenceKind::COUNT:
      return false;
  }
  return false;
}

/// Independently reconciles evidence into an initial state. Any fact that is not
/// established at the granted generation leaves the subject UNKNOWN.
/// Reconciliation notes are diagnostic only: a plan is judged by what it
/// depends on, not by unrelated evidence that happens to be unusable.
State reconcile(const PlanRequest& request,
                const FabricDefinition& definition,
                const Tables& tables,
                const AuthorityVector& authority,
                std::vector<std::string>* notes) {
  State state;
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

  std::map<EvidenceKey, std::vector<const EvidenceFact*>> grouped;
  for (const EvidenceFact& fact : request.evidence.facts) {
    if (!is_valid(fact.kind)) {
      if (notes != nullptr) notes->push_back("evidence kind is outside the defined domain");
      continue;
    }
    grouped[EvidenceKey{fact.kind, fact.subject}].push_back(&fact);
  }

  for (const auto& entry : grouped) {
    const EvidenceKind kind = entry.first.kind;
    const Subject subject = entry.first.subject;
    const std::size_t index = tables.subject(subject);
    if (index == static_cast<std::size_t>(-1)) {
      if (notes != nullptr) {
        notes->push_back("evidence references a subject that is not in the definition: " +
                         describe(subject));
      }
      continue;
    }
    bool usable_found = false;
    Sequence best_sequence{};
    std::uint64_t best_value = 0;
    Generation best_generation{};
    bool conflict = false;
    SubjectState worst = SubjectState::MISSING;
    for (const EvidenceFact* fact : entry.second) {
      if (fact->subject.kind != expected_subject(fact->kind)) {
        worst = SubjectState::INVALID;
        continue;
      }
      if (fact->source_domain != domain_of(fact->kind) ||
          !value_admissible(definition, tables, *fact)) {
        worst = SubjectState::INVALID;
        continue;
      }
      const AuthorityBinding* binding = authority.find(fact->source_domain);
      if (binding == nullptr) continue;
      if (fact->generation < binding->granted) {
        if (worst != SubjectState::INVALID) worst = SubjectState::STALE;
        continue;
      }
      if (fact->generation > binding->granted) {
        if (worst != SubjectState::INVALID) worst = SubjectState::AHEAD;
        continue;
      }
      if (fact->label == TrustLabel::UNSUPPORTED) {
        if (worst == SubjectState::MISSING) worst = SubjectState::UNSUPPORTED;
        continue;
      }
      if (fact->label == TrustLabel::UNKNOWN) {
        worst = SubjectState::INVALID;
        continue;
      }
      if (!usable_found) {
        usable_found = true;
        best_sequence = fact->sequence;
        best_value = fact->value;
        best_generation = fact->generation;
        continue;
      }
      if (fact->sequence > best_sequence) {
        best_sequence = fact->sequence;
        best_value = fact->value;
        best_generation = fact->generation;
        conflict = false;
        continue;
      }
      if (fact->sequence == best_sequence && fact->value != best_value) {
        conflict = true;
      }
    }
    if (conflict) {
      if (notes != nullptr) {
        notes->push_back("conflicting observations for " + describe(subject));
      }
      continue;
    }
    if (!usable_found) {
      if (notes != nullptr) {
        notes->push_back(std::string(to_string(worst)) + " evidence for " + describe(subject));
      }
      continue;
    }
    (void)best_generation;
    switch (kind) {
      case EvidenceKind::LINK_OPERATIONAL:
        state.link_up[index] = static_cast<std::uint8_t>(best_value != 0 ? 1 : 0);
        state.link_known[index] = 1;
        break;
      case EvidenceKind::NODE_OPERATIONAL:
        state.node_up[index] = static_cast<std::uint8_t>(best_value != 0 ? 1 : 0);
        state.node_known[index] = 1;
        break;
      case EvidenceKind::SERVICE_REACHABLE_ENDPOINTS:
        state.reachable[index] = static_cast<std::uint32_t>(best_value);
        state.service_known[index] = 1;
        break;
      case EvidenceKind::RESOURCE_AVAILABLE_UNITS:
        state.available[index] = static_cast<std::uint32_t>(best_value);
        state.resource_known[index] = 1;
        break;
      case EvidenceKind::RESOURCE_RESTORED:
        state.restored[index] = static_cast<std::uint8_t>(best_value != 0 ? 1 : 0);
        state.resource_known[index] = 1;
        break;
      case EvidenceKind::COUNT:
        break;
    }
  }
  return state;
}

bool precondition_ok(const Tables& tables,
                     const State& state,
                     const Precondition& precondition,
                     bool* known) {
  const std::size_t index = tables.subject(precondition.subject);
  if (index == static_cast<std::size_t>(-1)) {
    *known = false;
    return false;
  }
  switch (precondition.kind) {
    case PreconditionKind::LINK_OPERATIONAL:
      *known = state.link_known[index] != 0;
      return *known && state.link_up[index] != 0;
    case PreconditionKind::LINK_NOT_OPERATIONAL:
      *known = state.link_known[index] != 0;
      return *known && state.link_up[index] == 0;
    case PreconditionKind::NODE_OPERATIONAL:
      *known = state.node_known[index] != 0;
      return *known && state.node_up[index] != 0;
    case PreconditionKind::NODE_NOT_OPERATIONAL:
      *known = state.node_known[index] != 0;
      return *known && state.node_up[index] == 0;
    case PreconditionKind::SERVICE_REACHABLE_AT_LEAST:
      *known = state.service_known[index] != 0;
      return *known && state.reachable[index] >= precondition.value;
    case PreconditionKind::SERVICE_REACHABLE_AT_MOST:
      *known = state.service_known[index] != 0;
      return *known && state.reachable[index] <= precondition.value;
    case PreconditionKind::RESOURCE_AVAILABLE_AT_LEAST:
      *known = state.resource_known[index] != 0;
      return *known && state.available[index] >= precondition.value;
    case PreconditionKind::ACTION_EXECUTED_AT_LEAST:
      *known = true;
      return state.occurrences[index] >= precondition.value;
    case PreconditionKind::COUNT:
      *known = false;
      return false;
  }
  *known = false;
  return false;
}

}  // namespace

std::string ValidationReport::render() const {
  std::ostringstream out;
  out << (valid ? "VALID" : "INVALID") << " plan " << stated_plan_digest.hex() << " recomputed "
      << recomputed_plan_digest.hex() << " objective " << recomputed_objective.to_string() << '\n';
  for (const ValidationFinding& finding : findings) {
    out << "  " << to_string(finding.code);
    if (finding.step_index != kPlanLevel) out << " step " << finding.step_index;
    if (finding.subject.kind != SubjectKind::NONE) out << ' ' << describe(finding.subject);
    if (!finding.text.empty()) out << ": " << finding.text;
    out << '\n';
  }
  return out.str();
}

ValidationReport validate_plan(const PlanRequest& request, const RecoveryPlan& plan) {
  Report report;
  PlanRequest normalised = request;
  normalised.definition.canonicalise();
  normalised.evidence.canonicalise();
  normalised.authority.canonicalise();
  std::sort(normalised.fences.begin(), normalised.fences.end());
  const FabricDefinition& definition = normalised.definition;

  report.report().stated_plan_digest = plan.plan_digest;
  report.report().recomputed_plan_digest = plan.compute_digest();
  report.report().digest_matches =
      report.report().stated_plan_digest == report.report().recomputed_plan_digest;
  if (!report.report().digest_matches) {
    report.add(ReasonCode::VALIDATION_DIGEST_MISMATCH, kPlanLevel, {},
               "plan digest does not match the canonical encoding of the plan");
  }

  const Digest request_digest = normalised.digest();
  if (plan.request_digest != request_digest) {
    report.add(ReasonCode::VALIDATION_DIGEST_MISMATCH, kPlanLevel, {},
               "plan is bound to a different request digest");
  }
  if (plan.definition_digest != definition.digest()) {
    report.add(ReasonCode::VALIDATION_DIGEST_MISMATCH, kPlanLevel, {},
               "plan is bound to a different definition digest");
  }
  if (plan.evidence_digest != normalised.evidence.digest()) {
    report.add(ReasonCode::VALIDATION_DIGEST_MISMATCH, kPlanLevel, {},
               "plan is bound to a different evidence digest");
  }
  if (plan.authority_digest != normalised.authority.digest()) {
    report.add(ReasonCode::VALIDATION_DIGEST_MISMATCH, kPlanLevel, {},
               "plan is bound to a different authority digest");
  }
  if (plan.policy_digest != normalised.policy.digest()) {
    report.add(ReasonCode::VALIDATION_DIGEST_MISMATCH, kPlanLevel, {},
               "plan is bound to a different policy digest");
  }
  if (plan.request != normalised.id || plan.coordinator_epoch != normalised.coordinator_epoch ||
      plan.boot != normalised.boot || plan.attempt != normalised.attempt) {
    report.add(ReasonCode::VALIDATION_DIGEST_MISMATCH, kPlanLevel, {},
               "plan identity does not match the request identity");
  }
  for (const Fence& fence : normalised.fences) {
    if (fence.epoch > plan.coordinator_epoch ||
        (fence.epoch == plan.coordinator_epoch && fence.boot != plan.boot)) {
      report.add(ReasonCode::VALIDATION_FENCED, kPlanLevel, {},
                 "a fence revokes the authority the plan was issued under");
    }
  }
  {
    ExplanationLog definition_log(16);
    const Status status = validate_definition(definition, default_model_limits(), &definition_log);
    if (!status.ok()) {
      report.add(ReasonCode::REQUEST_INVALID_DEFINITION, kPlanLevel, {}, status.to_string());
    }
  }

  Tables tables;
  tables.build(definition);
  State state = reconcile(normalised, definition, tables, normalised.authority, nullptr);

  ObjectiveVector recomputed{};
  std::uint64_t previous_completeness = shortfall(definition, state, true);
  std::uint64_t previous_floor = shortfall(definition, state, false);
  std::vector<std::vector<std::pair<std::uint32_t, std::uint32_t>>> hold_history(
      definition.resources.size());

  std::uint32_t position = 0;
  for (const PlanStep& step : plan.steps) {
    if (step.index != position) {
      report.add(ReasonCode::VALIDATION_ORDERING_VIOLATION, position, {},
                 "step index does not match its position in the plan");
    }
    const auto action_it = tables.actions.find(step.action.value());
    if (action_it == tables.actions.end()) {
      report.add(ReasonCode::VALIDATION_ORDERING_VIOLATION, position, subject_of(step.action),
                 "step references an action that is not in the definition");
      ++position;
      continue;
    }
    const std::size_t action_index = action_it->second;
    const ActionSpec& action = definition.actions[action_index];
    if (state.occurrences[action_index] >= action.max_occurrences) {
      report.add(ReasonCode::VALIDATION_OCCURRENCE_EXCEEDED, position, subject_of(step.action),
                 "step exceeds the declared occurrence bound of the action");
    }
    if (step.occurrence != state.occurrences[action_index] + 1) {
      report.add(ReasonCode::VALIDATION_ORDERING_VIOLATION, position, subject_of(step.action),
                 "step occurrence number is not the next occurrence of the action");
    }
    for (const ActionDependency& dependency : action.dependencies) {
      const auto predecessor = tables.actions.find(dependency.predecessor.value());
      if (predecessor == tables.actions.end()) {
        report.add(ReasonCode::VALIDATION_ORDERING_VIOLATION, position,
                   subject_of(dependency.predecessor), "dependency references an unknown action");
        continue;
      }
      if (state.occurrences[predecessor->second] < dependency.min_occurrences) {
        report.add(ReasonCode::VALIDATION_ORDERING_VIOLATION, position,
                   subject_of(dependency.predecessor),
                   "dependency is not satisfied before this step");
      }
    }
    if (state.occurrences[action_index] == 0) {
      for (const ExclusionGroupId& group : action.exclusion_groups) {
        const auto group_it = tables.groups.find(group.value());
        if (group_it == tables.groups.end()) {
          report.add(ReasonCode::VALIDATION_EXCLUSION_VIOLATION, position, {}, "unknown group");
          continue;
        }
        std::uint32_t selected = 0;
        for (std::size_t candidate = 0; candidate < definition.actions.size(); ++candidate) {
          if (state.occurrences[candidate] == 0) continue;
          const ActionSpec& other = definition.actions[candidate];
          for (const ExclusionGroupId& other_group : other.exclusion_groups) {
            if (other_group == group) {
              ++selected;
              break;
            }
          }
        }
        if (selected >= definition.exclusion_groups[group_it->second].max_selected) {
          report.add(ReasonCode::VALIDATION_EXCLUSION_VIOLATION, position, {},
                     "exclusion group capacity is already consumed");
        }
      }
    }

    std::vector<EvidenceBinding> expected_bindings;
    for (const Precondition& precondition : action.preconditions) {
      bool known = false;
      const bool holds = precondition_ok(tables, state, precondition, &known);
      if (!known) {
        report.add(ReasonCode::VALIDATION_PRECONDITION_UNMET, position, precondition.subject,
                   "precondition subject is UNKNOWN at this point of the plan");
        continue;
      }
      if (!holds) {
        report.add(ReasonCode::VALIDATION_PRECONDITION_UNMET, position, precondition.subject,
                   std::string("precondition ") + to_string(precondition.kind) + " is not met");
      }
      const EvidenceKind kind = kind_of(precondition.kind);
      if (kind == EvidenceKind::COUNT) continue;
      // Recompute the binding independently: the newest admissible fact for the
      // subject at the granted generation.
      Sequence best_sequence{};
      bool found = false;
      Generation generation{};
      for (const EvidenceFact& fact : normalised.evidence.facts) {
        if (fact.kind != kind || fact.subject != precondition.subject) continue;
        if (fact.subject.kind != expected_subject(fact.kind)) continue;
        if (fact.source_domain != domain_of(fact.kind)) continue;
        if (fact.label != TrustLabel::REAL && fact.label != TrustLabel::SYNTHETIC) continue;
        if (!value_admissible(definition, tables, fact)) continue;
        const AuthorityBinding* binding = normalised.authority.find(fact.source_domain);
        if (binding == nullptr || fact.generation != binding->granted) continue;
        if (!found || fact.sequence > best_sequence) {
          best_sequence = fact.sequence;
          generation = fact.generation;
          found = true;
        }
      }
      if (found) {
        expected_bindings.push_back(EvidenceBinding{kind, precondition.subject, generation});
      }
    }
    std::sort(expected_bindings.begin(), expected_bindings.end());
    expected_bindings.erase(std::unique(expected_bindings.begin(), expected_bindings.end()),
                            expected_bindings.end());
    std::vector<EvidenceBinding> stated = step.evidence;
    std::sort(stated.begin(), stated.end());
    stated.erase(std::unique(stated.begin(), stated.end()), stated.end());
    if (stated != expected_bindings) {
      report.add(ReasonCode::VALIDATION_EVIDENCE_BINDING_MISMATCH, position, {},
                 "step evidence bindings do not match the independently derived binding set");
    }

    const BindingState binding_state = evaluate_domain(normalised.authority, step.required_domain);
    const AuthorityBinding* binding = normalised.authority.find(step.required_domain);
    if (binding == nullptr || binding_state != BindingState::CURRENT) {
      report.add(ReasonCode::VALIDATION_AUTHORITY_MISMATCH, position, {},
                 "step requires an authority domain that is not current");
    } else {
      if (step.required_generation != binding->granted) {
        report.add(ReasonCode::VALIDATION_AUTHORITY_MISMATCH, position, {},
                   "step binds a generation that is not the granted generation");
      }
      if (step.required_level != action.required_level ||
          step.required_domain != action.required_domain) {
        report.add(ReasonCode::VALIDATION_AUTHORITY_MISMATCH, position, {},
                   "step authority requirement does not match the action definition");
      }
      if (binding->level < step.required_level) {
        report.add(ReasonCode::VALIDATION_AUTHORITY_MISMATCH, position, {},
                   "granted authority level is below the level the step requires");
      }
    }
    if (step.issued_level != AuthorityLevel::RECOMMENDATION) {
      report.add(ReasonCode::VALIDATION_AUTHORITY_MISMATCH, position, {},
                 "a planner issued authority above RECOMMENDATION");
    }
    if (action.reversibility == Reversibility::IRREVERSIBLE) {
      if (!step.irreversible || !step.compensation.is_zero()) {
        report.add(ReasonCode::VALIDATION_COMPENSATION_MISSING, position, subject_of(step.action),
                   "irreversible action must be marked irreversible with no compensation");
      }
    } else {
      if (step.irreversible) {
        report.add(ReasonCode::VALIDATION_COMPENSATION_MISSING, position, subject_of(step.action),
                   "reversible action is marked irreversible");
      }
      if (step.compensation != action.compensation ||
          tables.actions.find(step.compensation.value()) == tables.actions.end()) {
        report.add(ReasonCode::VALIDATION_COMPENSATION_MISSING, position, subject_of(step.action),
                   "compensation action is missing or does not match the definition");
      }
      if (!normalised.policy.allow_irreversible_actions) {
        // reversible actions are always allowed
      }
    }
    if (action.reversibility == Reversibility::IRREVERSIBLE &&
        !normalised.policy.allow_irreversible_actions) {
      report.add(ReasonCode::REQUEST_POLICY_RESTRICTED_ACTION, position, subject_of(step.action),
                 "policy excludes irreversible actions but the plan contains one");
    }
    if (position >= normalised.policy.max_plan_steps) {
      report.add(ReasonCode::VALIDATION_ORDERING_VIOLATION, position, {},
                 "plan length exceeds the policy bound");
    }

    // Resource accounting, recomputed from the step sequence alone.
    for (std::size_t index = 0; index < action.resource_uses.size(); ++index) {
      const ResourceUse& use = action.resource_uses[index];
      const auto resource_it = tables.resources.find(use.resource.value());
      if (resource_it == tables.resources.end()) {
        report.add(ReasonCode::VALIDATION_RESOURCE_VIOLATION, position, subject_of(use.resource),
                   "step uses a resource that is not in the definition");
        continue;
      }
      const ResourceSpec& resource = definition.resources[resource_it->second];
      if (resource.kind == ResourceKind::CONSUMABLE) {
        if (state.resource_known[resource_it->second] == 0) {
          report.add(ReasonCode::VALIDATION_RESOURCE_VIOLATION, position, subject_of(use.resource),
                     "consumable resource availability is UNKNOWN");
        } else if (state.available[resource_it->second] < use.units) {
          report.add(ReasonCode::VALIDATION_RESOURCE_VIOLATION, position, subject_of(use.resource),
                     "step consumes more units than remain available");
        }
      } else {
        std::uint32_t overlapping = use.units;
        for (const auto& hold : hold_history[resource_it->second]) {
          if (position - hold.first < resource.hold_steps ||
              (resource.hold_steps == 0 && position == hold.first)) {
            overlapping += hold.second;
          }
        }
        if (overlapping > resource.capacity) {
          report.add(ReasonCode::VALIDATION_RESOURCE_VIOLATION, position, subject_of(use.resource),
                     "overlapping holds exceed the capacity of the reusable resource");
        }
      }
    }

    // Effects
    for (const Effect& effect : action.effects) {
      const std::size_t index = tables.subject(effect.subject);
      if (index == static_cast<std::size_t>(-1)) {
        report.add(ReasonCode::REQUEST_INVALID_DEFINITION, position, effect.subject,
                   "effect references an unknown subject");
        continue;
      }
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
          if (static_cast<std::uint64_t>(effect.value) >
              definition.services[index].max_reachable) {
            report.add(ReasonCode::VALIDATION_SAFETY_VIOLATION, position, effect.subject,
                       "effect exceeds the structural maximum of the service");
          } else {
            state.reachable[index] = static_cast<std::uint32_t>(effect.value);
            state.service_known[index] = 1;
          }
          break;
        case EffectKind::SERVICE_REACHABLE_DELTA: {
          if (state.service_known[index] == 0) {
            if (definition.services[index].required_reachable > 0) {
              report.add(ReasonCode::VALIDATION_SAFETY_VIOLATION, position, effect.subject,
                         "step changes a service whose reachability is UNKNOWN");
            }
            break;
          }
          const std::int64_t updated = static_cast<std::int64_t>(state.reachable[index]) +
                                       effect.value;
          if (updated < 0 ||
              static_cast<std::uint64_t>(updated) >
                  definition.services[index].max_reachable) {
            report.add(ReasonCode::VALIDATION_SAFETY_VIOLATION, position, effect.subject,
                       "reachability would leave the valid range");
          } else {
            state.reachable[index] = static_cast<std::uint32_t>(updated);
          }
          break;
        }
        case EffectKind::MARK_RESOURCE_RESTORED:
          state.restored[index] = 1;
          state.resource_known[index] = 1;
          break;
        case EffectKind::SET_RESOURCE_AVAILABLE:
          if (static_cast<std::uint64_t>(effect.value) >
              definition.resources[index].capacity) {
            report.add(ReasonCode::VALIDATION_RESOURCE_VIOLATION, position, effect.subject,
                       "availability effect exceeds the capacity of the resource");
          } else {
            state.available[index] = static_cast<std::uint32_t>(effect.value);
            state.resource_known[index] = 1;
          }
          break;
        case EffectKind::COUNT:
          report.add(ReasonCode::REQUEST_UNSUPPORTED_PROBLEM, position, effect.subject,
                     "effect kind is outside the defined domain");
          break;
      }
    }
    for (const ResourceUse& use : action.resource_uses) {
      const auto resource_it = tables.resources.find(use.resource.value());
      if (resource_it == tables.resources.end()) continue;
      if (definition.resources[resource_it->second].kind == ResourceKind::CONSUMABLE &&
          state.resource_known[resource_it->second] != 0) {
        if (state.available[resource_it->second] < use.units) {
          report.add(ReasonCode::VALIDATION_RESOURCE_VIOLATION, position, subject_of(use.resource),
                     "consumption underflows the available units");
          state.available[resource_it->second] = 0;
        } else {
          state.available[resource_it->second] -= use.units;
        }
      }
      if (definition.resources[resource_it->second].kind == ResourceKind::REUSABLE) {
        hold_history[resource_it->second].emplace_back(position, use.units);
      }
    }

    const std::uint64_t floor_after = shortfall(definition, state, false);
    if (floor_after > previous_floor) {
      ++recomputed[0];
      recomputed[1] += floor_after - previous_floor;
      report.add(ReasonCode::VALIDATION_SAFETY_VIOLATION, position, {},
                 "step increases the shortfall of a service below its required floor");
    }
    previous_floor = floor_after;
    const std::uint64_t completeness_after = shortfall(definition, state, true);
    if (completeness_after > previous_completeness) {
      recomputed[2] += completeness_after - previous_completeness;
    }
    previous_completeness = completeness_after;

    std::uint64_t sum = 0;
    if (!add_overflow(recomputed[3], action.blast_radius, &sum)) recomputed[3] = sum;
    sum = 0;
    if (!add_overflow(recomputed[4], 1, &sum)) recomputed[4] = sum;
    sum = 0;
    if (!add_overflow(recomputed[5], action.disruption, &sum)) recomputed[5] = sum;
    sum = 0;
    if (!add_overflow(recomputed[6], action.cost_units, &sum)) recomputed[6] = sum;
    sum = 0;
    if (!add_overflow(recomputed[7], action.duration_ticks, &sum)) recomputed[7] = sum;

    std::uint64_t tick = 0;
    if (!add_overflow(state.tick, action.duration_ticks, &tick)) state.tick = tick;
    state.occurrences[action_index] += 1;
    ++position;
  }

  for (const GoalSpec& goal : definition.goals) {
    const std::size_t index = tables.subject(goal.subject);
    if (index == static_cast<std::size_t>(-1)) {
      report.add(ReasonCode::VALIDATION_GOAL_UNMET, kPlanLevel, goal.subject,
                 "goal references a subject that is not in the definition");
      continue;
    }
    bool satisfied = false;
    switch (goal.kind) {
      case GoalKind::LINK_OPERATIONAL:
        satisfied = state.link_known[index] != 0 && state.link_up[index] != 0;
        break;
      case GoalKind::NODE_OPERATIONAL:
        satisfied = state.node_known[index] != 0 && state.node_up[index] != 0;
        break;
      case GoalKind::RESOURCE_RESTORED:
        satisfied = state.resource_known[index] != 0 && state.restored[index] != 0;
        break;
      case GoalKind::SERVICE_REACHABLE_AT_LEAST:
        satisfied = state.service_known[index] != 0 && state.reachable[index] >= goal.value;
        break;
      case GoalKind::COUNT:
        satisfied = false;
        break;
    }
    if (!satisfied) {
      report.add(ReasonCode::VALIDATION_GOAL_UNMET, kPlanLevel, goal.subject,
                 "goal is not satisfied by the final state");
    }
  }

  report.report().recomputed_objective = recomputed;
  report.report().objective_matches =
      compare_objective(recomputed, plan.objective) == 0;
  if (!report.report().objective_matches) {
    report.add(ReasonCode::VALIDATION_OBJECTIVE_MISMATCH, kPlanLevel, {},
               "stated objective " + plan.objective.to_string() + " differs from the recomputed " +
                   recomputed.to_string());
  }
  report.report().valid = report.report().findings.empty();
  return report.report();
}

ValidationReport validate_certificate(const PlanRequest& request,
                                      const InfeasibilityCertificate& certificate) {
  Report report;
  PlanRequest normalised = request;
  normalised.definition.canonicalise();
  normalised.evidence.canonicalise();
  normalised.authority.canonicalise();
  std::sort(normalised.fences.begin(), normalised.fences.end());
  const FabricDefinition& definition = normalised.definition;

  if (certificate.request_digest != normalised.digest()) {
    report.add(ReasonCode::VALIDATION_DIGEST_MISMATCH, kPlanLevel, {},
               "certificate is bound to a different request digest");
  }
  if (certificate.policy_digest != normalised.policy.digest()) {
    report.add(ReasonCode::VALIDATION_DIGEST_MISMATCH, kPlanLevel, {},
               "certificate is bound to a different policy digest");
  }
  if (certificate.assumptions.empty()) {
    report.add(ReasonCode::VALIDATION_OBJECTIVE_MISMATCH, kPlanLevel, {},
               "a proof of infeasibility must state its assumptions explicitly");
  }
  Tables tables;
  tables.build(definition);

  switch (certificate.kind) {
    case ProofKind::DEPENDENCY_CYCLE: {
      if (certificate.cycle.size() < 2) {
        report.add(ReasonCode::PROOF_DEPENDENCY_CYCLE, kPlanLevel, {},
                   "cycle certificate carries no cycle");
        break;
      }
      // Re-derive: every consecutive pair must be a declared dependency, and the
      // cycle must close on itself.
      bool ok = true;
      for (std::size_t index = 0; index + 1 < certificate.cycle.size(); ++index) {
        const ActionId from = certificate.cycle[index];
        const ActionId to = certificate.cycle[index + 1];
        const auto to_it = tables.actions.find(to.value());
        if (to_it == tables.actions.end()) {
          ok = false;
          break;
        }
        bool edge = false;
        for (const ActionDependency& dependency : definition.actions[to_it->second].dependencies) {
          if (dependency.predecessor == from) edge = true;
        }
        if (!edge) {
          ok = false;
          break;
        }
      }
      if (certificate.cycle.front() != certificate.cycle.back()) ok = false;
      if (!ok) {
        report.add(ReasonCode::PROOF_DEPENDENCY_CYCLE, kPlanLevel, {},
                   "declared cycle is not a cycle of the dependency relation");
      }
      break;
    }
    case ProofKind::GOAL_UPPER_BOUND: {
      bool matched = false;
      for (const GoalSpec& goal : definition.goals) {
        if (goal.subject != certificate.unreachable_subject || goal.value != certificate.required_value) {
          continue;
        }
        std::uint64_t bound = 0;
        if (goal.kind == GoalKind::SERVICE_REACHABLE_AT_LEAST) {
          const auto it = tables.services.find(goal.subject.id);
          if (it == tables.services.end()) break;
          const ServiceSpec& service = definition.services[it->second];
          bound = service.max_reachable;
        } else {
          bound = 0;
        }
        if (certificate.unreachable_value <= bound) matched = true;
      }
      if (!matched) {
        report.add(ReasonCode::PROOF_GOAL_UPPER_BOUND, kPlanLevel, certificate.unreachable_subject,
                   "declared upper bound is not below the structural maximum of the subject");
      }
      break;
    }
    case ProofKind::EXHAUSTIVE_SEARCH: {
      if (certificate.nodes_expanded == 0) {
        report.add(ReasonCode::PROOF_EXHAUSTIVE_SEARCH, kPlanLevel, {},
                   "an exhaustive proof must report the explored node count");
      }
      // An exhaustive proof may only be claimed when every subject a step or a
      // goal depends on was established by evidence at the granted generation.
      std::vector<std::string> notes;
      const State initial =
          reconcile(normalised, definition, tables, normalised.authority, &notes);
      std::set<Subject> referenced;
      for (const ActionSpec& action : definition.actions) {
        for (const Precondition& precondition : action.preconditions) {
          referenced.insert(precondition.subject);
        }
      }
      for (const GoalSpec& goal : definition.goals) {
        referenced.insert(goal.subject);
      }
      for (const Subject& subject : referenced) {
        const std::size_t index = tables.subject(subject);
        if (index == static_cast<std::size_t>(-1)) continue;
        bool established = true;
        switch (subject.kind) {
          case SubjectKind::LINK: established = initial.link_known[index] != 0; break;
          case SubjectKind::NODE: established = initial.node_known[index] != 0; break;
          case SubjectKind::SERVICE: established = initial.service_known[index] != 0; break;
          case SubjectKind::RESOURCE: established = initial.resource_known[index] != 0; break;
          default: break;
        }
        if (!established) {
          report.add(ReasonCode::PROOF_EXHAUSTIVE_SEARCH, kPlanLevel, subject,
                     "exhaustive proof claimed while a referenced subject is UNKNOWN");
        }
      }
      break;
    }
    case ProofKind::COUNT:
      report.add(ReasonCode::REQUEST_UNSUPPORTED_PROBLEM, kPlanLevel, {},
                 "certificate proof kind is outside the defined domain");
      break;
  }
  report.report().valid = report.report().findings.empty();
  return report.report();
}

}  // namespace nrp
