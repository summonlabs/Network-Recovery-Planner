// Network Recovery Planner - deterministic synthetic fabric fixtures.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// Everything produced here is SYNTHETIC: it is a deterministic model of a
// disrupted fabric, not telemetry from real switching, NIC or RDMA hardware.
#ifndef NRP_TEST_FIXTURE_HPP
#define NRP_TEST_FIXTURE_HPP

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include "nrp/codec.hpp"
#include "nrp/domain.hpp"
#include "nrp/planner.hpp"
#include "nrp/reference_solver.hpp"
#include "nrp/validate.hpp"
#include "support/test_support.hpp"

namespace nrp::test {

/// Generation every synthetic observation is produced at. The authority vector
/// grants exactly this generation, so nothing is stale or ahead by accident.
inline constexpr std::uint64_t kGeneration = 3;
inline constexpr std::uint64_t kEvidenceSequenceBase = 10;

inline AuthorityVector synthetic_authority(Epoch epoch, BootId boot, std::uint64_t generation,
                                           AuthorityLevel level = AuthorityLevel::AUTHORIZATION) {
  AuthorityVector authority;
  authority.coordinator_epoch = epoch;
  authority.boot = boot;
  for (std::uint8_t domain = 0; domain < static_cast<std::uint8_t>(AuthorityDomain::COUNT);
       ++domain) {
    AuthorityBinding binding;
    binding.domain = static_cast<AuthorityDomain>(domain);
    binding.authority = AuthorityId::from_value(100 + domain);
    binding.required = Generation{generation};
    binding.granted = Generation{generation};
    binding.level = level;
    authority.bindings.push_back(binding);
  }
  authority.canonicalise();
  return authority;
}

/// Fixture policy: irreversible actions are allowed (the library default is
/// deliberately conservative and excludes them).
inline PlanPolicy fixture_policy(std::uint64_t max_plan_steps = 6) {
  PlanPolicy policy;
  policy.allow_irreversible_actions = true;
  policy.max_plan_steps = max_plan_steps;
  return policy;
}

class FabricBuilder {
 public:
  FabricBuilder() {
    epoch_ = Epoch::from_value(1);
    boot_ = BootId::from_value(7);
    evidence_.coordinator_epoch = epoch_;
    evidence_.boot = boot_;
  }

  NodeId add_node(bool protected_node = false) {
    NodeSpec node;
    node.id = NodeId::from_value(next_node_++);
    node.protected_node = protected_node;
    definition_.nodes.push_back(node);
    return node.id;
  }

  LinkId add_link(NodeId a, NodeId b) {
    LinkSpec link;
    link.id = LinkId::from_value(next_link_++);
    link.endpoint_a = a;
    link.endpoint_b = b;
    definition_.links.push_back(link);
    return link.id;
  }

  ServiceId add_service(std::uint32_t required, std::uint32_t target, std::uint32_t max_reachable,
                        bool protected_service) {
    ServiceSpec service;
    service.id = ServiceId::from_value(next_service_++);
    service.required_reachable = required;
    service.target_reachable = target;
    service.max_reachable = max_reachable;
    service.protected_service = protected_service;
    definition_.services.push_back(service);
    return service.id;
  }

  ResourceId add_resource(ResourceKind kind, std::uint32_t capacity, std::uint32_t hold_steps) {
    ResourceSpec resource;
    resource.id = ResourceId::from_value(next_resource_++);
    resource.kind = kind;
    resource.capacity = capacity;
    resource.hold_steps = hold_steps;
    definition_.resources.push_back(resource);
    return resource.id;
  }

  ActionId add_action(ActionSpec spec) {
    spec.id = ActionId::from_value(next_action_++);
    definition_.actions.push_back(std::move(spec));
    return definition_.actions.back().id;
  }

  void add_goal(GoalSpec goal) { definition_.goals.push_back(goal); }

  void add_exclusion_group(ExclusionGroupId id, std::uint32_t max_selected) {
    ExclusionGroup group;
    group.id = id;
    group.max_selected = max_selected;
    definition_.exclusion_groups.push_back(group);
  }

  void observe(EvidenceKind kind, Subject subject, std::uint64_t value,
               std::uint64_t generation = kGeneration, std::uint64_t sequence = kEvidenceSequenceBase,
               TrustLabel label = TrustLabel::SYNTHETIC,
               AuthorityDomain domain = AuthorityDomain::FABRIC_STATE,
               AuthorityId source = AuthorityId::from_value(9)) {
    EvidenceFact fact;
    fact.id = EvidenceId::from_value(next_evidence_++);
    fact.kind = kind;
    fact.subject = subject;
    fact.value = value;
    fact.generation = Generation{generation};
    fact.source_domain = domain;
    fact.source = source;
    fact.label = label;
    fact.sequence = Sequence{sequence};
    evidence_.facts.push_back(fact);
  }

  void observe_link(LinkId link, bool operational, std::uint64_t generation = kGeneration) {
    observe(EvidenceKind::LINK_OPERATIONAL, subject_of(link), operational ? 1 : 0, generation);
  }

  void observe_node(NodeId node, bool operational, std::uint64_t generation = kGeneration) {
    observe(EvidenceKind::NODE_OPERATIONAL, subject_of(node), operational ? 1 : 0, generation);
  }

  void observe_service(ServiceId service, std::uint32_t reachable,
                       std::uint64_t generation = kGeneration) {
    observe(EvidenceKind::SERVICE_REACHABLE_ENDPOINTS, subject_of(service), reachable, generation);
  }

  void observe_resource_available(ResourceId resource, std::uint32_t units,
                                  std::uint64_t generation = kGeneration) {
    observe(EvidenceKind::RESOURCE_AVAILABLE_UNITS, subject_of(resource), units, generation,
            kEvidenceSequenceBase, TrustLabel::SYNTHETIC, AuthorityDomain::RESOURCE_LEASE);
  }

  void observe_resource_restored(ResourceId resource, bool restored,
                                 std::uint64_t generation = kGeneration) {
    observe(EvidenceKind::RESOURCE_RESTORED, subject_of(resource), restored ? 1 : 0, generation,
            kEvidenceSequenceBase, TrustLabel::SYNTHETIC, AuthorityDomain::RESOURCE_LEASE);
  }

  void set_epoch(Epoch epoch) {
    epoch_ = epoch;
    evidence_.coordinator_epoch = epoch;
  }

  void set_boot(BootId boot) {
    boot_ = boot;
    evidence_.boot = boot;
  }

  void set_authority(AuthorityVector authority) { authority_override_ = std::move(authority); }
  void add_fence(Fence fence) { fences_.push_back(std::move(fence)); }

  const FabricDefinition& definition() const { return definition_; }
  const EvidenceBundle& evidence() const { return evidence_; }
  Epoch epoch() const { return epoch_; }
  BootId boot() const { return boot_; }

  PlanRequest build(RequestId id = RequestId::from_value(1),
                    AttemptId attempt = AttemptId::from_value(1),
                    PlanPolicy policy = PlanPolicy{}) const {
    PlanRequest request;
    request.id = id;
    request.coordinator_epoch = epoch_;
    request.boot = boot_;
    request.attempt = attempt;
    request.definition = definition_;
    request.evidence = evidence_;
    request.authority = authority_override_.bindings.empty()
                            ? synthetic_authority(epoch_, boot_, kGeneration)
                            : authority_override_;
    request.policy = policy;
    request.fences = fences_;
    request.definition.canonicalise();
    request.evidence.canonicalise();
    request.authority.canonicalise();
    std::sort(request.fences.begin(), request.fences.end());
    return request;
  }

  /// Flips a policy bound to zero, used by adversarial tests.
  static PlanRequest with_policy(PlanRequest request, PlanPolicy policy) {
    request.policy = policy;
    return request;
  }

 private:
  FabricDefinition definition_;
  EvidenceBundle evidence_;
  AuthorityVector authority_override_;
  std::vector<Fence> fences_;
  Epoch epoch_;
  BootId boot_;
  std::uint64_t next_node_ = 1;
  std::uint64_t next_link_ = 1;
  std::uint64_t next_service_ = 1;
  std::uint64_t next_resource_ = 1;
  std::uint64_t next_action_ = 1;
  std::uint64_t next_evidence_ = 1;
};

/// Canonical teaching fixture used across suites.
///
///   nodes n1,n2,n3; links l1(n1-n2) and l2(n2-n3); service s1 (floor 1,
///   target 2, maximum 2, protected); resource r1 consumable capacity 2.
///   a1 restores l1 (+1 endpoint, cost 10, blast 1), a2 replaces l2 (+1 endpoint,
///   cost 20, blast 2), a3 is a reversible drain that costs one endpoint.
///   Initially both links are down and the service is at zero endpoints, so the
///   floor is already breached by the disruption and any plan must not deepen it.
struct TeachingFabric {
  FabricBuilder builder;
  NodeId n1, n2, n3;
  LinkId l1, l2;
  ServiceId s1;
  ResourceId r1;
  ActionId a1, a2, a3, a4;

  TeachingFabric() {
    n1 = builder.add_node(false);
    n2 = builder.add_node(false);
    n3 = builder.add_node(true);
    l1 = builder.add_link(n1, n2);
    l2 = builder.add_link(n2, n3);
    s1 = builder.add_service(1, 2, 2, true);
    r1 = builder.add_resource(ResourceKind::CONSUMABLE, 2, 0);

    n1 = builder.add_node(false);
    n2 = builder.add_node(false);
    n3 = builder.add_node(true);
    l1 = builder.add_link(n1, n2);
    l2 = builder.add_link(n2, n3);
    s1 = builder.add_service(1, 2, 2, true);
    r1 = builder.add_resource(ResourceKind::CONSUMABLE, 2, 0);

    ActionSpec spec1;
    spec1.name = "restore-l1";
    spec1.kind = ActionKind::RESTORE;
    spec1.reversibility = Reversibility::IRREVERSIBLE;
    spec1.blast_radius = 1;
    spec1.disruption = 1;
    spec1.cost_units = 10;
    spec1.duration_ticks = 5;
    spec1.required_domain = AuthorityDomain::RECOVERY_ADMISSION;
    spec1.required_level = AuthorityLevel::AUTHORIZATION;
    spec1.preconditions.push_back(Precondition{PreconditionKind::LINK_NOT_OPERATIONAL,
                                               subject_of(l1), 0});
    spec1.effects.push_back(Effect{EffectKind::SET_LINK_OPERATIONAL, subject_of(l1), 1});
    spec1.effects.push_back(Effect{EffectKind::SERVICE_REACHABLE_DELTA, subject_of(s1), 1});
    spec1.resource_uses.push_back(ResourceUse{r1, 1});
    a1 = builder.add_action(spec1);

    ActionSpec spec2;
    spec2.name = "replace-l2";
    spec2.kind = ActionKind::REPLACE;
    spec2.reversibility = Reversibility::IRREVERSIBLE;
    spec2.blast_radius = 2;
    spec2.disruption = 2;
    spec2.cost_units = 20;
    spec2.duration_ticks = 7;
    spec2.required_domain = AuthorityDomain::RECOVERY_ADMISSION;
    spec2.required_level = AuthorityLevel::AUTHORIZATION;
    spec2.preconditions.push_back(Precondition{PreconditionKind::LINK_NOT_OPERATIONAL,
                                               subject_of(l2), 0});
    spec2.effects.push_back(Effect{EffectKind::SET_LINK_OPERATIONAL, subject_of(l2), 1});
    spec2.effects.push_back(Effect{EffectKind::SERVICE_REACHABLE_DELTA, subject_of(s1), 1});
    spec2.resource_uses.push_back(ResourceUse{r1, 1});
    a2 = builder.add_action(spec2);

    ActionSpec spec3;
    spec3.name = "drain-n3";
    spec3.kind = ActionKind::DRAIN;
    spec3.reversibility = Reversibility::IRREVERSIBLE;
    spec3.blast_radius = 3;
    spec3.disruption = 4;
    spec3.cost_units = 5;
    spec3.duration_ticks = 2;
    spec3.required_domain = AuthorityDomain::RECOVERY_ADMISSION;
    spec3.required_level = AuthorityLevel::AUTHORIZATION;
    spec3.preconditions.push_back(Precondition{PreconditionKind::NODE_OPERATIONAL,
                                               subject_of(n3), 0});
    spec3.effects.push_back(Effect{EffectKind::SET_NODE_OPERATIONAL, subject_of(n3), 0});
    a3 = builder.add_action(spec3);

    ActionSpec spec4;
    spec4.name = "isolate-l1";
    spec4.kind = ActionKind::ISOLATE;
    spec4.reversibility = Reversibility::IRREVERSIBLE;
    spec4.blast_radius = 0;
    spec4.disruption = 0;
    spec4.cost_units = 1;
    spec4.duration_ticks = 1;
    spec4.required_domain = AuthorityDomain::RECOVERY_ADMISSION;
    spec4.required_level = AuthorityLevel::AUTHORIZATION;
    spec4.effects.push_back(Effect{EffectKind::SET_LINK_OPERATIONAL, subject_of(l1), 0});
    a4 = builder.add_action(spec4);

    builder.observe_link(l1, false);
    builder.observe_link(l2, false);
    builder.observe_node(n1, true);
    builder.observe_node(n2, true);
    builder.observe_node(n3, true);
    builder.observe_service(s1, 0);
    builder.observe_resource_available(r1, 2);
    builder.observe_resource_restored(r1, false);

    GoalSpec goal = make_service_goal(s1, 2);
    builder.add_goal(goal);
  }

  static GoalSpec make_service_goal(ServiceId service, std::uint64_t value) {
    GoalSpec goal;
    goal.kind = GoalKind::SERVICE_REACHABLE_AT_LEAST;
    goal.subject = subject_of(service);
    goal.value = value;
    goal.weight = 1;
    return goal;
  }

  PlanRequest request() const {
    return builder.build(RequestId::from_value(1), AttemptId::from_value(1), fixture_policy());
  }
};

/// Deterministic random instance generator used by the differential suite.
/// The produced instances are always structurally valid definitions with
/// complete evidence, so the reference solver's answer is exact.
inline PlanRequest random_scenario(std::uint64_t seed, std::uint32_t case_index,
                                   std::uint64_t max_plan_steps = 5) {
  Rng rng(seed * 1000003ull + case_index);
  FabricBuilder builder;
  const std::uint32_t node_count = 2 + static_cast<std::uint32_t>(rng.below(2));
  std::vector<NodeId> nodes;
  for (std::uint32_t index = 0; index < node_count; ++index) {
    nodes.push_back(builder.add_node(rng.below(4) == 0));
  }
  const std::uint32_t link_count = 1 + static_cast<std::uint32_t>(rng.below(3));
  std::vector<LinkId> links;
  for (std::uint32_t index = 0; index < link_count; ++index) {
    const std::uint32_t a = static_cast<std::uint32_t>(rng.below(nodes.size()));
    std::uint32_t b = static_cast<std::uint32_t>(rng.below(nodes.size()));
    if (b == a) b = (a + 1) % static_cast<std::uint32_t>(nodes.size());
    links.push_back(builder.add_link(nodes[a], nodes[b]));
  }
  const std::uint32_t service_count = 1 + static_cast<std::uint32_t>(rng.below(2));
  std::vector<ServiceId> services;
  for (std::uint32_t index = 0; index < service_count; ++index) {
    const std::uint32_t max_reachable = 2 + static_cast<std::uint32_t>(rng.below(2));
    const std::uint32_t required = static_cast<std::uint32_t>(rng.below(max_reachable + 1));
    const std::uint32_t target =
        required + static_cast<std::uint32_t>(rng.below(max_reachable - required + 1));
    services.push_back(builder.add_service(required, target, max_reachable, rng.coin()));
  }
  std::vector<ResourceId> resources;
  if (rng.below(2) == 1) {
    const ResourceKind kind = rng.coin() ? ResourceKind::CONSUMABLE : ResourceKind::REUSABLE;
    const std::uint32_t capacity = 1 + static_cast<std::uint32_t>(rng.below(3));
    const std::uint32_t hold = kind == ResourceKind::REUSABLE
                                   ? static_cast<std::uint32_t>(rng.below(3))
                                   : 0;
    resources.push_back(builder.add_resource(kind, capacity, hold));
  }

  const std::uint32_t action_count = 2 + static_cast<std::uint32_t>(rng.below(3));
  std::vector<ActionId> actions;
  for (std::uint32_t index = 0; index < action_count; ++index) {
    ActionSpec spec;
    spec.name = "a" + std::to_string(index);
    spec.kind = static_cast<ActionKind>(rng.below(static_cast<std::uint64_t>(ActionKind::COUNT)));
    spec.reversibility = Reversibility::IRREVERSIBLE;
    spec.blast_radius = static_cast<std::uint32_t>(rng.below(4));
    spec.disruption = static_cast<std::uint32_t>(rng.below(4));
    spec.cost_units = rng.below(20);
    spec.duration_ticks = rng.below(8);
    spec.max_occurrences = rng.below(4) == 0 ? 2 : 1;
    spec.required_domain = AuthorityDomain::RECOVERY_ADMISSION;
    spec.required_level = AuthorityLevel::AUTHORIZATION;

    const std::uint32_t precondition_count = static_cast<std::uint32_t>(rng.below(3));
    for (std::uint32_t p = 0; p < precondition_count; ++p) {
      Precondition precondition;
      switch (rng.below(4)) {
        case 0:
          precondition.kind = PreconditionKind::LINK_OPERATIONAL;
          precondition.subject = subject_of(links[rng.below(links.size())]);
          break;
        case 1:
          precondition.kind = PreconditionKind::LINK_NOT_OPERATIONAL;
          precondition.subject = subject_of(links[rng.below(links.size())]);
          break;
        case 2:
          precondition.kind = PreconditionKind::NODE_OPERATIONAL;
          precondition.subject = subject_of(nodes[rng.below(nodes.size())]);
          break;
        default:
          precondition.kind = PreconditionKind::SERVICE_REACHABLE_AT_LEAST;
          precondition.subject = subject_of(services[rng.below(services.size())]);
          precondition.value = rng.below(2);
          break;
      }
      spec.preconditions.push_back(precondition);
    }

    const std::uint32_t effect_count = 1 + static_cast<std::uint32_t>(rng.below(2));
    for (std::uint32_t e = 0; e < effect_count; ++e) {
      Effect effect;
      switch (rng.below(6)) {
        case 0:
          effect.kind = EffectKind::SET_LINK_OPERATIONAL;
          effect.subject = subject_of(links[rng.below(links.size())]);
          effect.value = 1;
          break;
        case 1:
          effect.kind = EffectKind::SET_LINK_OPERATIONAL;
          effect.subject = subject_of(links[rng.below(links.size())]);
          effect.value = 0;
          break;
        case 2:
          effect.kind = EffectKind::SET_NODE_OPERATIONAL;
          effect.subject = subject_of(nodes[rng.below(nodes.size())]);
          effect.value = 1;
          break;
        case 3:
          effect.kind = EffectKind::MARK_RESOURCE_RESTORED;
          if (resources.empty()) continue;
          effect.subject = subject_of(resources.front());
          effect.value = 1;
          break;
        case 4: {
          effect.kind = EffectKind::SERVICE_REACHABLE_DELTA;
          const std::size_t which = static_cast<std::size_t>(rng.below(services.size()));
          effect.subject = subject_of(services[which]);
          const ServiceSpec* service = builder.definition().find_service(services[which]);
          const std::int64_t delta = rng.coin() ? 1 : -1;
          effect.value = delta;
          if (service != nullptr && service->required_reachable > 0 && delta < 0) {
            effect.value = 0;
          }
          break;
        }
        default:
          effect.kind = EffectKind::SET_SERVICE_REACHABLE;
          effect.subject = subject_of(services[rng.below(services.size())]);
          effect.value = static_cast<std::int64_t>(rng.below(3));
          break;
      }
      spec.effects.push_back(effect);
    }
    if (!resources.empty() && rng.below(3) == 0) {
      ResourceUse use;
      use.resource = resources.front();
      const ResourceSpec* resource = builder.definition().find_resource(resources.front());
      use.units = 1 + static_cast<std::uint32_t>(rng.below(resource != nullptr ? resource->capacity : 1));
      spec.resource_uses.push_back(use);
    }
    if (!actions.empty() && rng.below(3) == 0) {
      ActionDependency dependency;
      dependency.predecessor = actions[rng.below(actions.size())];
      dependency.min_occurrences = 1;
      spec.dependencies.push_back(dependency);
    }
    actions.push_back(builder.add_action(spec));
  }
  const std::uint32_t goal_count = 1 + static_cast<std::uint32_t>(rng.below(2));
  for (std::uint32_t index = 0; index < goal_count; ++index) {
    GoalSpec goal;
    goal.weight = 1;
    switch (rng.below(4)) {
      case 0:
        goal.kind = GoalKind::LINK_OPERATIONAL;
        goal.subject = subject_of(links[rng.below(links.size())]);
        break;
      case 1:
        goal.kind = GoalKind::NODE_OPERATIONAL;
        goal.subject = subject_of(nodes[rng.below(nodes.size())]);
        break;
      case 2:
        goal.kind = GoalKind::RESOURCE_RESTORED;
        if (resources.empty()) {
          goal.kind = GoalKind::LINK_OPERATIONAL;
          goal.subject = subject_of(links[rng.below(links.size())]);
        } else {
          goal.subject = subject_of(resources.front());
        }
        break;
      default: {
        const std::size_t which = static_cast<std::size_t>(rng.below(services.size()));
        const ServiceSpec* service = builder.definition().find_service(services[which]);
        goal.kind = GoalKind::SERVICE_REACHABLE_AT_LEAST;
        goal.subject = subject_of(services[which]);
        goal.value = service == nullptr ? 1 : rng.below(service->max_reachable + 1);
        break;
      }
    }
    builder.add_goal(goal);
  }

  for (const LinkId link : links) builder.observe_link(link, rng.coin());
  for (const NodeId node : nodes) builder.observe_node(node, rng.below(3) != 0);
  for (const ServiceId service : services) {
    const ServiceSpec* spec = builder.definition().find_service(service);
    builder.observe_service(service,
                            spec == nullptr ? 0
                                            : static_cast<std::uint32_t>(rng.below(spec->max_reachable + 1)));
  }
  for (const ResourceId resource : resources) {
    const ResourceSpec* spec = builder.definition().find_resource(resource);
    builder.observe_resource_available(
        resource, spec == nullptr ? 0 : static_cast<std::uint32_t>(rng.below(spec->capacity + 1)));
    builder.observe_resource_restored(resource, rng.coin());
  }

  PlanPolicy policy;
  policy.allow_irreversible_actions = true;
  policy.max_plan_steps = max_plan_steps;
  policy.max_nodes_expanded = 200000;
  policy.max_generated_states = 400000;
  policy.max_frontier_entries = 200000;
  return builder.build(RequestId::from_value(1 + case_index), AttemptId::from_value(1), policy);
}

/// Permutes every collection of a request. Planning must be invariant.
inline PlanRequest permuted_request(const PlanRequest& request, std::uint64_t seed) {
  Rng rng(seed);
  PlanRequest permuted = request;
  const auto shuffle = [&rng](auto& container) {
    for (std::size_t index = container.size(); index > 1; --index) {
      const std::size_t other = static_cast<std::size_t>(rng.below(index));
      std::swap(container[index - 1], container[other]);
    }
  };
  shuffle(permuted.definition.nodes);
  shuffle(permuted.definition.links);
  shuffle(permuted.definition.services);
  shuffle(permuted.definition.resources);
  shuffle(permuted.definition.actions);
  shuffle(permuted.definition.goals);
  shuffle(permuted.definition.exclusion_groups);
  for (ActionSpec& action : permuted.definition.actions) {
    shuffle(action.preconditions);
    shuffle(action.effects);
    shuffle(action.resource_uses);
    shuffle(action.dependencies);
    shuffle(action.exclusion_groups);
  }
  shuffle(permuted.evidence.facts);
  shuffle(permuted.authority.bindings);
  shuffle(permuted.fences);
  return permuted;
}

}  // namespace nrp::test

#endif  // NRP_TEST_FIXTURE_HPP
