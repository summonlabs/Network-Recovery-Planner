// Network Recovery Planner - canonical decoders for domain objects.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "nrp/codec.hpp"

#include "nrp/result.hpp"

namespace nrp {
namespace {

Subject read_subject(CanonicalReader& reader, const char* what) {
  Subject subject;
  subject.kind = reader.enum_value<SubjectKind>(7, what);
  subject.id = reader.u64();
  if (reader.ok() && subject.kind == SubjectKind::NONE) {
    reader.fail(StatusCode::PROTOCOL_ERROR, std::string("subject kind NONE is not addressable in ") + what);
  }
  return subject;
}

}  // namespace

Status decode_definition(CanonicalReader& reader, const ModelLimits& limits, FabricDefinition* out) {
  FabricDefinition definition;

  const std::uint32_t node_count = reader.bounded_count(limits.max_nodes, "nodes");
  if (!reader.ok()) return reader.status();
  definition.nodes.reserve(node_count);
  for (std::uint32_t index = 0; index < node_count; ++index) {
    NodeSpec node;
    node.id = NodeId::from_value(reader.u64());
    node.protected_node = reader.boolean();
    if (!reader.ok()) return reader.status();
    definition.nodes.push_back(node);
  }

  const std::uint32_t link_count = reader.bounded_count(limits.max_links, "links");
  if (!reader.ok()) return reader.status();
  definition.links.reserve(link_count);
  for (std::uint32_t index = 0; index < link_count; ++index) {
    LinkSpec link;
    link.id = LinkId::from_value(reader.u64());
    link.endpoint_a = NodeId::from_value(reader.u64());
    link.endpoint_b = NodeId::from_value(reader.u64());
    if (!reader.ok()) return reader.status();
    definition.links.push_back(link);
  }

  const std::uint32_t service_count = reader.bounded_count(limits.max_services, "services");
  if (!reader.ok()) return reader.status();
  definition.services.reserve(service_count);
  for (std::uint32_t index = 0; index < service_count; ++index) {
    ServiceSpec service;
    service.id = ServiceId::from_value(reader.u64());
    service.required_reachable = reader.u32();
    service.target_reachable = reader.u32();
    service.max_reachable = reader.u32();
    service.protected_service = reader.boolean();
    if (!reader.ok()) return reader.status();
    definition.services.push_back(service);
  }

  const std::uint32_t resource_count = reader.bounded_count(limits.max_resources, "resources");
  if (!reader.ok()) return reader.status();
  definition.resources.reserve(resource_count);
  for (std::uint32_t index = 0; index < resource_count; ++index) {
    ResourceSpec resource;
    resource.id = ResourceId::from_value(reader.u64());
    resource.kind = reader.enum_value<ResourceKind>(2, "resource kind");
    resource.capacity = reader.u32();
    resource.hold_steps = reader.u32();
    if (!reader.ok()) return reader.status();
    definition.resources.push_back(resource);
  }

  const std::uint32_t action_count = reader.bounded_count(limits.max_actions, "actions");
  if (!reader.ok()) return reader.status();
  definition.actions.reserve(action_count);
  for (std::uint32_t index = 0; index < action_count; ++index) {
    ActionSpec action;
    action.id = ActionId::from_value(reader.u64());
    action.name = reader.str(limits.max_string_length);
    action.kind = reader.enum_value<ActionKind>(7, "action kind");
    action.reversibility = reader.enum_value<Reversibility>(2, "action reversibility");
    action.compensation = ActionId::from_value(reader.u64());
    action.blast_radius = reader.u32();
    action.disruption = reader.u32();
    action.cost_units = reader.u64();
    action.duration_ticks = reader.u64();
    action.max_occurrences = reader.u32();
    action.required_domain = reader.enum_value<AuthorityDomain>(5, "action required_domain");
    action.required_level = reader.enum_value<AuthorityLevel>(7, "action required_level");
    if (!reader.ok()) return reader.status();

    const std::uint32_t precondition_count =
        reader.bounded_count(limits.max_preconditions_per_action, "preconditions");
    if (!reader.ok()) return reader.status();
    action.preconditions.reserve(precondition_count);
    for (std::uint32_t p = 0; p < precondition_count; ++p) {
      Precondition precondition;
      precondition.kind = reader.enum_value<PreconditionKind>(8, "precondition kind");
      precondition.subject = read_subject(reader, "precondition");
      precondition.value = reader.u64();
      if (!reader.ok()) return reader.status();
      action.preconditions.push_back(precondition);
    }

    const std::uint32_t effect_count = reader.bounded_count(limits.max_effects_per_action, "effects");
    if (!reader.ok()) return reader.status();
    action.effects.reserve(effect_count);
    for (std::uint32_t e = 0; e < effect_count; ++e) {
      Effect effect;
      effect.kind = reader.enum_value<EffectKind>(6, "effect kind");
      effect.subject = read_subject(reader, "effect");
      effect.value = reader.i64();
      if (!reader.ok()) return reader.status();
      action.effects.push_back(effect);
    }

    const std::uint32_t use_count =
        reader.bounded_count(limits.max_resources, "resource uses per action");
    if (!reader.ok()) return reader.status();
    action.resource_uses.reserve(use_count);
    for (std::uint32_t r = 0; r < use_count; ++r) {
      ResourceUse use;
      use.resource = ResourceId::from_value(reader.u64());
      use.units = reader.u32();
      if (!reader.ok()) return reader.status();
      action.resource_uses.push_back(use);
    }

    const std::uint32_t dependency_count =
        reader.bounded_count(limits.max_actions, "action dependencies");
    if (!reader.ok()) return reader.status();
    action.dependencies.reserve(dependency_count);
    for (std::uint32_t r = 0; r < dependency_count; ++r) {
      ActionDependency dependency;
      dependency.predecessor = ActionId::from_value(reader.u64());
      dependency.min_occurrences = reader.u32();
      if (!reader.ok()) return reader.status();
      action.dependencies.push_back(dependency);
    }

    const std::uint32_t group_count =
        reader.bounded_count(limits.max_exclusion_groups, "action exclusion groups");
    if (!reader.ok()) return reader.status();
    action.exclusion_groups.reserve(group_count);
    for (std::uint32_t g = 0; g < group_count; ++g) {
      action.exclusion_groups.push_back(ExclusionGroupId::from_value(reader.u64()));
      if (!reader.ok()) return reader.status();
    }

    definition.actions.push_back(std::move(action));
  }

  const std::uint32_t goal_count = reader.bounded_count(limits.max_goals, "goals");
  if (!reader.ok()) return reader.status();
  definition.goals.reserve(goal_count);
  for (std::uint32_t index = 0; index < goal_count; ++index) {
    GoalSpec goal;
    goal.kind = reader.enum_value<GoalKind>(4, "goal kind");
    goal.subject = read_subject(reader, "goal");
    goal.value = reader.u64();
    goal.weight = reader.u32();
    if (!reader.ok()) return reader.status();
    definition.goals.push_back(goal);
  }

  const std::uint32_t group_count = reader.bounded_count(limits.max_exclusion_groups, "exclusion groups");
  if (!reader.ok()) return reader.status();
  definition.exclusion_groups.reserve(group_count);
  for (std::uint32_t index = 0; index < group_count; ++index) {
    ExclusionGroup group;
    group.id = ExclusionGroupId::from_value(reader.u64());
    group.max_selected = reader.u32();
    if (!reader.ok()) return reader.status();
    definition.exclusion_groups.push_back(group);
  }

  *out = std::move(definition);
  return Status::success();
}

Status decode_evidence(CanonicalReader& reader, const ModelLimits& limits, EvidenceBundle* out) {
  EvidenceBundle bundle;
  bundle.coordinator_epoch = Epoch::from_value(reader.u64());
  bundle.boot = BootId::from_value(reader.u64());
  const std::uint32_t fact_count = reader.bounded_count(limits.max_evidence_facts, "evidence facts");
  if (!reader.ok()) return reader.status();
  bundle.facts.reserve(fact_count);
  for (std::uint32_t index = 0; index < fact_count; ++index) {
    EvidenceFact fact;
    fact.id = EvidenceId::from_value(reader.u64());
    fact.kind = reader.enum_value<EvidenceKind>(5, "evidence kind");
    fact.subject = read_subject(reader, "evidence");
    fact.value = reader.u64();
    fact.generation = Generation{reader.u64()};
    fact.source_domain = reader.enum_value<AuthorityDomain>(5, "evidence source_domain");
    fact.source = AuthorityId::from_value(reader.u64());
    fact.label = reader.enum_value<TrustLabel>(4, "evidence trust label");
    fact.sequence = Sequence{reader.u64()};
    if (!reader.ok()) return reader.status();
    bundle.facts.push_back(fact);
  }
  *out = std::move(bundle);
  return Status::success();
}

Status decode_authority(CanonicalReader& reader, const ModelLimits& limits, AuthorityVector* out) {
  AuthorityVector vector;
  vector.coordinator_epoch = Epoch::from_value(reader.u64());
  vector.boot = BootId::from_value(reader.u64());
  const std::uint32_t binding_count = reader.bounded_count(limits.max_authority_bindings, "authority bindings");
  if (!reader.ok()) return reader.status();
  vector.bindings.reserve(binding_count);
  for (std::uint32_t index = 0; index < binding_count; ++index) {
    AuthorityBinding binding;
    binding.domain = reader.enum_value<AuthorityDomain>(5, "authority domain");
    binding.authority = AuthorityId::from_value(reader.u64());
    binding.required = Generation{reader.u64()};
    binding.granted = Generation{reader.u64()};
    binding.level = reader.enum_value<AuthorityLevel>(7, "authority level");
    if (!reader.ok()) return reader.status();
    vector.bindings.push_back(binding);
  }
  *out = std::move(vector);
  return Status::success();
}

Status decode_policy(CanonicalReader& reader, PlanPolicy* out) {
  PlanPolicy policy;
  policy.allow_irreversible_actions = reader.boolean();
  policy.require_current_authority = reader.boolean();
  policy.max_plan_steps = reader.u64();
  policy.max_nodes_expanded = reader.u64();
  policy.max_generated_states = reader.u64();
  policy.max_frontier_entries = reader.u64();
  policy.budget_scale = reader.u32();
  if (!reader.ok()) return reader.status();
  if (policy.max_plan_steps == 0) {
    return Status::error(StatusCode::INVALID_ARGUMENT, "policy max_plan_steps must be at least one");
  }
  if (policy.max_nodes_expanded == 0 || policy.max_generated_states == 0 ||
      policy.max_frontier_entries == 0) {
    return Status::error(StatusCode::INVALID_ARGUMENT, "policy search budgets must be at least one");
  }
  *out = policy;
  return Status::success();
}

void encode_fence(const Fence& fence, CanonicalWriter& writer) {
  writer.u64(fence.epoch.value());
  writer.u64(fence.boot.value());
  writer.u8(static_cast<std::uint8_t>(fence.domain));
  writer.u64(fence.minimum_generation.value);
  writer.u64(fence.sequence.value);
  writer.str(fence.reason);
}

Status decode_fence(CanonicalReader& reader, Fence* out) {
  Fence fence;
  fence.epoch = Epoch::from_value(reader.u64());
  fence.boot = BootId::from_value(reader.u64());
  fence.domain = reader.enum_value<AuthorityDomain>(5, "fence domain");
  fence.minimum_generation = Generation{reader.u64()};
  fence.sequence = Sequence{reader.u64()};
  fence.reason = reader.str(128);
  if (!reader.ok()) return reader.status();
  *out = std::move(fence);
  return Status::success();
}

Status decode_plan_request_body(CanonicalReader& reader,
                                const ModelLimits& limits,
                                PlanRequest* out) {
  PlanRequest request;
  request.id = RequestId::from_value(reader.u64());
  request.coordinator_epoch = Epoch::from_value(reader.u64());
  request.boot = BootId::from_value(reader.u64());
  request.attempt = AttemptId::from_value(reader.u64());
  if (!reader.ok()) return reader.status();
  Status status = decode_definition(reader, limits, &request.definition);
  if (!status.ok()) return status;
  status = decode_evidence(reader, limits, &request.evidence);
  if (!status.ok()) return status;
  status = decode_authority(reader, limits, &request.authority);
  if (!status.ok()) return status;
  status = decode_policy(reader, &request.policy);
  if (!status.ok()) return status;
  const std::uint32_t fence_count = reader.bounded_count(limits.max_fences, "fences");
  if (!reader.ok()) return reader.status();
  request.fences.reserve(fence_count);
  for (std::uint32_t index = 0; index < fence_count; ++index) {
    Fence fence;
    status = decode_fence(reader, &fence);
    if (!status.ok()) return status;
    request.fences.push_back(std::move(fence));
  }
  *out = std::move(request);
  return Status::success();
}

Result<PlanRequest> decode_plan_request(const std::vector<std::uint8_t>& bytes,
                                        const ModelLimits& limits) {
  CanonicalReader reader(bytes);
  PlanRequest request;
  Status status = decode_plan_request_body(reader, limits, &request);
  if (!status.ok()) return status;
  status = reader.require_end();
  if (!status.ok()) return status;
  return request;
}

void encode_explanation(CanonicalWriter& writer, const Explanation& explanation) {
  writer.u8(static_cast<std::uint8_t>(explanation.code));
  writer.u8(static_cast<std::uint8_t>(explanation.subject.kind));
  writer.u64(explanation.subject.id);
  writer.u64(explanation.detail_a);
  writer.u64(explanation.detail_b);
  writer.str(explanation.text);
}

Status decode_explanation(CanonicalReader& reader, const ModelLimits& limits, Explanation* out) {
  Explanation explanation;
  explanation.code = reader.enum_value<ReasonCode>(static_cast<std::uint8_t>(ReasonCode::COUNT),
                                                   "reason code");
  explanation.subject.kind = reader.enum_value<SubjectKind>(7, "explanation subject kind");
  explanation.subject.id = reader.u64();
  explanation.detail_a = reader.u64();
  explanation.detail_b = reader.u64();
  explanation.text = reader.str(limits.max_string_length * 4);
  if (!reader.ok()) return reader.status();
  *out = std::move(explanation);
  return Status::success();
}

void encode_plan(const RecoveryPlan& plan, CanonicalWriter& writer) {
  writer.u64(plan.id.value());
  writer.u64(plan.request.value());
  writer.u64(plan.coordinator_epoch.value());
  writer.u64(plan.boot.value());
  writer.u64(plan.attempt.value());
  writer.u32(static_cast<std::uint32_t>(plan.steps.size()));
  for (const PlanStep& step : plan.steps) {
    writer.u32(step.index);
    writer.u64(step.action.value());
    writer.u32(step.occurrence);
    writer.u64(step.start_tick);
    writer.u64(step.end_tick);
    writer.u8(static_cast<std::uint8_t>(step.required_domain));
    writer.u8(static_cast<std::uint8_t>(step.required_level));
    writer.u64(step.required_generation.value);
    writer.u8(static_cast<std::uint8_t>(step.issued_level));
    writer.u32(static_cast<std::uint32_t>(step.evidence.size()));
    for (const EvidenceBinding& binding : step.evidence) {
      writer.u8(static_cast<std::uint8_t>(binding.kind));
      writer.u8(static_cast<std::uint8_t>(binding.subject.kind));
      writer.u64(binding.subject.id);
      writer.u64(binding.generation.value);
    }
    writer.boolean(step.irreversible);
    writer.u64(step.compensation.value());
  }
  plan.objective.encode(writer);
  writer.u64(plan.request_digest.hi);
  writer.u64(plan.request_digest.lo);
  writer.u64(plan.definition_digest.hi);
  writer.u64(plan.definition_digest.lo);
  writer.u64(plan.evidence_digest.hi);
  writer.u64(plan.evidence_digest.lo);
  writer.u64(plan.authority_digest.hi);
  writer.u64(plan.authority_digest.lo);
  writer.u64(plan.policy_digest.hi);
  writer.u64(plan.policy_digest.lo);
  writer.u32(static_cast<std::uint32_t>(plan.explanations.size()));
  for (const Explanation& explanation : plan.explanations) {
    encode_explanation(writer, explanation);
  }
}

Status decode_plan(CanonicalReader& reader, const ModelLimits& limits, RecoveryPlan* out) {
  RecoveryPlan plan;
  plan.id = PlanId::from_value(reader.u64());
  plan.request = RequestId::from_value(reader.u64());
  plan.coordinator_epoch = Epoch::from_value(reader.u64());
  plan.boot = BootId::from_value(reader.u64());
  plan.attempt = AttemptId::from_value(reader.u64());
  const std::uint32_t step_count = reader.bounded_count(limits.max_actions * limits.max_action_occurrences + 1,
                                                        "plan steps");
  if (!reader.ok()) return reader.status();
  plan.steps.reserve(step_count);
  for (std::uint32_t index = 0; index < step_count; ++index) {
    PlanStep step;
    step.index = reader.u32();
    step.action = ActionId::from_value(reader.u64());
    step.occurrence = reader.u32();
    step.start_tick = reader.u64();
    step.end_tick = reader.u64();
    step.required_domain = reader.enum_value<AuthorityDomain>(5, "step required_domain");
    step.required_level = reader.enum_value<AuthorityLevel>(7, "step required_level");
    step.required_generation = Generation{reader.u64()};
    step.issued_level = reader.enum_value<AuthorityLevel>(7, "step issued_level");
    if (!reader.ok()) return reader.status();
    const std::uint32_t binding_count =
        reader.bounded_count(limits.max_evidence_facts, "step evidence bindings");
    if (!reader.ok()) return reader.status();
    step.evidence.reserve(binding_count);
    for (std::uint32_t b = 0; b < binding_count; ++b) {
      EvidenceBinding binding;
      binding.kind = reader.enum_value<EvidenceKind>(5, "evidence binding kind");
      binding.subject = read_subject(reader, "evidence binding");
      binding.generation = Generation{reader.u64()};
      if (!reader.ok()) return reader.status();
      step.evidence.push_back(binding);
    }
    step.irreversible = reader.boolean();
    step.compensation = ActionId::from_value(reader.u64());
    if (!reader.ok()) return reader.status();
    plan.steps.push_back(std::move(step));
  }
  for (std::size_t component = 0; component < kObjectiveComponents; ++component) {
    plan.objective[component] = reader.u64();
  }
  plan.request_digest.hi = reader.u64();
  plan.request_digest.lo = reader.u64();
  plan.definition_digest.hi = reader.u64();
  plan.definition_digest.lo = reader.u64();
  plan.evidence_digest.hi = reader.u64();
  plan.evidence_digest.lo = reader.u64();
  plan.authority_digest.hi = reader.u64();
  plan.authority_digest.lo = reader.u64();
  plan.policy_digest.hi = reader.u64();
  plan.policy_digest.lo = reader.u64();
  if (!reader.ok()) return reader.status();
  const std::uint32_t explanation_count = reader.bounded_count(256, "plan explanations");
  if (!reader.ok()) return reader.status();
  plan.explanations.reserve(explanation_count);
  for (std::uint32_t index = 0; index < explanation_count; ++index) {
    Explanation explanation;
    Status status = decode_explanation(reader, limits, &explanation);
    if (!status.ok()) return status;
    plan.explanations.push_back(std::move(explanation));
  }
  *out = std::move(plan);
  return Status::success();
}

}  // namespace nrp
