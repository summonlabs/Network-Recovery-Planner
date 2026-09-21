// Network Recovery Planner - adversarial cases built to break greedy planning.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include <string>

#include "nrp/planner.hpp"
#include "nrp/reference_solver.hpp"
#include "nrp/validate.hpp"
#include "support/fixture.hpp"
#include "support/test_support.hpp"

using namespace nrp;
using namespace nrp::test;

namespace {

PlanPolicy permissive(std::uint64_t steps = 6) {
  PlanPolicy policy;
  policy.allow_irreversible_actions = true;
  policy.max_plan_steps = steps;
  return policy;
}

}  // namespace

NRP_TEST(adversarial, cheapest_first_action_is_a_trap) {
  // The cheapest action by every additive measure is useless; only the
  // expensive action reaches the goal. A cost-greedy planner picks the trap.
  FabricBuilder builder;
  const NodeId n1 = builder.add_node();
  const NodeId n2 = builder.add_node();
  const LinkId target = builder.add_link(n1, n2);
  const LinkId decoy = builder.add_link(n1, n2);
  ActionSpec cheap;
  cheap.effects.push_back(Effect{EffectKind::SET_LINK_OPERATIONAL, subject_of(decoy), 1});
  cheap.cost_units = 1;
  cheap.blast_radius = 1;
  const ActionId cheap_id = builder.add_action(cheap);
  ActionSpec expensive;
  expensive.effects.push_back(Effect{EffectKind::SET_LINK_OPERATIONAL, subject_of(target), 1});
  expensive.cost_units = 100;
  expensive.blast_radius = 4;
  expensive.disruption = 3;
  const ActionId expensive_id = builder.add_action(expensive);
  builder.observe_link(target, false);
  builder.observe_link(decoy, false);
  builder.observe_node(n1, true);
  builder.observe_node(n2, true);
  GoalSpec goal;
  goal.kind = GoalKind::LINK_OPERATIONAL;
  goal.subject = subject_of(target);
  goal.value = 1;
  builder.add_goal(goal);
  const PlanRequest request = FabricBuilder::with_policy(builder.build(), permissive());
  Planner planner;
  const PlanningResult result = planner.plan(request);
  NRP_REQUIRE(result.plan.has_value());
  NRP_CHECK_EQ(result.plan->steps.size(), static_cast<std::size_t>(1));
  NRP_CHECK_EQ(result.plan->steps[0].action, expensive_id);
  NRP_CHECK(cheap_id != expensive_id);
}

NRP_TEST(adversarial, local_optimum_loses_to_the_global_objective) {
  // Two routes to the same goal: two cheap low-blast steps, or one step with a
  // larger blast radius. The lexicographic objective prefers the smaller blast
  // radius even though the single step is cheaper and shorter.
  FabricBuilder builder;
  const NodeId n1 = builder.add_node();
  const NodeId n2 = builder.add_node();
  const ServiceId service = builder.add_service(0, 2, 4, false);
  ActionSpec first;
  first.effects.push_back(Effect{EffectKind::SERVICE_REACHABLE_DELTA, subject_of(service), 1});
  first.blast_radius = 1;
  first.cost_units = 40;
  const ActionId first_id = builder.add_action(first);
  ActionSpec second;
  second.effects.push_back(Effect{EffectKind::SERVICE_REACHABLE_DELTA, subject_of(service), 1});
  second.blast_radius = 1;
  second.cost_units = 40;
  const ActionId second_id = builder.add_action(second);
  ActionSpec big;
  big.effects.push_back(Effect{EffectKind::SET_SERVICE_REACHABLE, subject_of(service), 2});
  big.blast_radius = 5;
  big.cost_units = 1;
  const ActionId big_id = builder.add_action(big);
  builder.observe_node(n1, true);
  builder.observe_node(n2, true);
  builder.observe_service(service, 0);
  GoalSpec goal;
  goal.kind = GoalKind::SERVICE_REACHABLE_AT_LEAST;
  goal.subject = subject_of(service);
  goal.value = 2;
  builder.add_goal(goal);
  const PlanRequest request = FabricBuilder::with_policy(builder.build(), permissive());
  Planner planner;
  const PlanningResult result = planner.plan(request);
  NRP_REQUIRE(result.plan.has_value());
  NRP_CHECK_EQ(result.plan->steps.size(), static_cast<std::size_t>(2));
  NRP_CHECK_EQ(result.plan->objective[3], 2ull);
  NRP_CHECK(result.plan->steps[0].action != big_id);
  NRP_CHECK(result.plan->steps[1].action != big_id);
  NRP_CHECK(validate_plan(request, *result.plan).valid);
  NRP_CHECK(first_id != second_id);
}

NRP_TEST(adversarial, unsafe_steps_are_never_taken) {
  // The only action that reaches the goal would push a protected service below
  // its floor, so no plan exists: the planner must prove that rather than emit a
  // plan that breaches the floor.
  FabricBuilder builder;
  const NodeId n1 = builder.add_node();
  const NodeId n2 = builder.add_node();
  const LinkId link = builder.add_link(n1, n2);
  const ServiceId service = builder.add_service(2, 2, 2, true);
  ActionSpec spec;
  spec.preconditions.push_back(
      Precondition{PreconditionKind::LINK_NOT_OPERATIONAL, subject_of(link), 0});
  spec.effects.push_back(Effect{EffectKind::SET_LINK_OPERATIONAL, subject_of(link), 1});
  spec.effects.push_back(Effect{EffectKind::SERVICE_REACHABLE_DELTA, subject_of(service), -1});
  builder.add_action(spec);
  builder.observe_link(link, false);
  builder.observe_node(n1, true);
  builder.observe_node(n2, true);
  builder.observe_service(service, 2);
  GoalSpec goal;
  goal.kind = GoalKind::LINK_OPERATIONAL;
  goal.subject = subject_of(link);
  goal.value = 1;
  builder.add_goal(goal);
  const PlanRequest request = FabricBuilder::with_policy(builder.build(), permissive());
  Planner planner;
  const PlanningResult result = planner.plan(request);
  NRP_CHECK_EQ(std::string(to_string(result.decision)), std::string("PROVEN_INFEASIBLE"));
  NRP_CHECK(!result.plan.has_value());
  NRP_CHECK(validate_certificate(request, *result.certificate).valid);
}

NRP_TEST(adversarial, protectedservice_never_drops_below_its_floor) {
  FabricBuilder builder;
  const NodeId n1 = builder.add_node();
  const NodeId n2 = builder.add_node();
  const ServiceId service = builder.add_service(2, 3, 4, true);
  ActionSpec degrade;
  degrade.effects.push_back(Effect{EffectKind::SERVICE_REACHABLE_DELTA, subject_of(service), -1});
  degrade.cost_units = 1;
  const ActionId degrade_id = builder.add_action(degrade);
  ActionSpec repair;
  repair.effects.push_back(Effect{EffectKind::SERVICE_REACHABLE_DELTA, subject_of(service), 1});
  repair.cost_units = 10;
  const ActionId repair_id = builder.add_action(repair);
  builder.observe_node(n1, true);
  builder.observe_node(n2, true);
  builder.observe_service(service, 2);
  GoalSpec goal;
  goal.kind = GoalKind::SERVICE_REACHABLE_AT_LEAST;
  goal.subject = subject_of(service);
  goal.value = 3;
  builder.add_goal(goal);
  const PlanRequest request = FabricBuilder::with_policy(builder.build(), permissive());
  Planner planner;
  const PlanningResult result = planner.plan(request);
  NRP_REQUIRE(result.plan.has_value());
  NRP_CHECK_EQ(result.plan->steps.size(), static_cast<std::size_t>(1));
  NRP_CHECK_EQ(result.plan->steps[0].action, repair_id);
  NRP_CHECK(result.plan->steps[0].action != degrade_id);
  NRP_CHECK_EQ(result.plan->objective[0], 0ull);
  NRP_CHECK_EQ(result.plan->objective[1], 0ull);
  NRP_CHECK(validate_plan(request, *result.plan).valid);
}

NRP_TEST(adversarial, search_budget_exhaustion_never_fakes_infeasibility) {
  const PlanRequest request = random_scenario(9, 0, 8);
  PlanPolicy policy = request.policy;
  policy.max_nodes_expanded = 1;
  policy.max_generated_states = 1;
  policy.max_frontier_entries = 1;
  const PlanRequest limited = FabricBuilder::with_policy(request, policy);
  Planner planner;
  const PlanningResult result = planner.plan(limited);
  NRP_CHECK(result.decision != PlanDecision::PROVEN_INFEASIBLE ||
            result.certificate.has_value());
  if (result.decision == PlanDecision::INDETERMINATE_SEARCH_LIMIT) {
    NRP_CHECK(result.stats.budget_exhausted);
    NRP_CHECK(!result.certificate.has_value());
  }
}

NRP_TEST(adversarial, oversized_definitions_are_refused) {
  FabricBuilder builder;
  const NodeId n1 = builder.add_node();
  (void)n1;
  for (std::uint32_t index = 0; index < 40; ++index) {
    ActionSpec spec;
    builder.add_action(spec);
  }
  PlanRequest request = builder.build();
  ModelLimits limits = default_model_limits();
  limits.max_actions = 8;
  Planner planner(limits);
  const PlanningResult result = planner.plan(request);
  NRP_CHECK_EQ(std::string(to_string(result.decision)),
               std::string("REJECTED_INVALID_REQUEST"));
}

NRP_TEST(adversarial, zero_identities_are_refused) {
  TeachingFabric fabric;
  PlanRequest request = fabric.request();
  request.id = RequestId{};
  Planner planner;
  NRP_CHECK_EQ(std::string(to_string(planner.plan(request).decision)),
               std::string("REJECTED_UNSUPPORTED_PROBLEM"));
  PlanRequest second = fabric.request();
  second.attempt = AttemptId{};
  NRP_CHECK_EQ(std::string(to_string(planner.plan(second).decision)),
               std::string("REJECTED_UNSUPPORTED_PROBLEM"));
}

NRP_TEST(adversarial, evidence_from_another_epoch_is_refused) {
  TeachingFabric fabric;
  PlanRequest request = fabric.request();
  request.evidence.coordinator_epoch = Epoch::from_value(request.coordinator_epoch.value() - 1);
  Planner planner;
  NRP_CHECK_EQ(std::string(to_string(planner.plan(request).decision)),
               std::string("REJECTED_STALE_AUTHORITY"));
  PlanRequest ahead = fabric.request();
  ahead.evidence.coordinator_epoch = Epoch::from_value(ahead.coordinator_epoch.value() + 1);
  NRP_CHECK_EQ(std::string(to_string(planner.plan(ahead).decision)),
               std::string("REJECTED_INVALID_REQUEST"));
}

NRP_TEST(adversarial, contradictory_evidence_yields_indeterminate) {
  TeachingFabric fabric;
  FabricBuilder builder = fabric.builder;
  builder.observe(EvidenceKind::SERVICE_REACHABLE_ENDPOINTS, subject_of(fabric.s1), 1, kGeneration,
                  kEvidenceSequenceBase);
  const PlanRequest request = builder.build();
  Planner planner;
  const PlanningResult result = planner.plan(request);
  NRP_CHECK_EQ(std::string(to_string(result.decision)),
               std::string("INDETERMINATE_INCOMPLETE_EVIDENCE"));
  NRP_CHECK(!result.plan.has_value());
  NRP_CHECK(!result.certificate.has_value());
}

NRP_TEST(adversarial, resource_exhaustion_is_deterministic) {
  TeachingFabric fabric;
  PlanRequest request = fabric.request();
  request.definition.resources[0].capacity = 0;
  for (EvidenceFact& fact : request.evidence.facts) {
    if (fact.kind == EvidenceKind::RESOURCE_AVAILABLE_UNITS) fact.value = 0;
  }
  request.definition.canonicalise();
  request.evidence.canonicalise();
  Planner planner;
  const PlanningResult first = planner.plan(request);
  const PlanningResult second = planner.plan(request);
  NRP_CHECK(first.decision == second.decision);
  NRP_CHECK(first.decision == PlanDecision::REJECTED_INVALID_REQUEST ||
            first.decision == PlanDecision::PROVEN_INFEASIBLE);
}

NRP_TEST(adversarial, occurrence_bounds_allow_explicit_iteration) {
  FabricBuilder builder;
  const NodeId n1 = builder.add_node();
  const NodeId n2 = builder.add_node();
  const LinkId link = builder.add_link(n1, n2);
  ActionSpec attempt;
  attempt.max_occurrences = 3;
  attempt.effects.push_back(Effect{EffectKind::SET_LINK_OPERATIONAL, subject_of(link), 1});
  attempt.cost_units = 5;
  const ActionId attempt_id = builder.add_action(attempt);
  builder.observe_link(link, false);
  builder.observe_node(n1, true);
  builder.observe_node(n2, true);
  GoalSpec goal;
  goal.kind = GoalKind::LINK_OPERATIONAL;
  goal.subject = subject_of(link);
  goal.value = 1;
  builder.add_goal(goal);
  const PlanRequest request = FabricBuilder::with_policy(builder.build(), permissive());
  Planner planner;
  const PlanningResult result = planner.plan(request);
  NRP_REQUIRE(result.plan.has_value());
  NRP_CHECK_EQ(result.plan->steps.size(), static_cast<std::size_t>(1));
  NRP_CHECK_EQ(result.plan->steps[0].action, attempt_id);
  NRP_CHECK_EQ(result.plan->steps[0].occurrence, 1u);
  NRP_CHECK(validate_plan(request, *result.plan).valid);
}

NRP_TEST(adversarial, scarce_resource_forces_a_worse_local_choice) {
  // Two mutually exclusive repairs consume the same single unit; only the more
  // expensive one satisfies the goal, so the cheaper action must be skipped even
  // though it is applicable first.
  FabricBuilder builder;
  const NodeId n1 = builder.add_node();
  const NodeId n2 = builder.add_node();
  const LinkId strong = builder.add_link(n1, n2);
  const LinkId weak = builder.add_link(n1, n2);
  const ServiceId service = builder.add_service(0, 3, 3, false);
  const ResourceId spare = builder.add_resource(ResourceKind::CONSUMABLE, 1, 0);
  ActionSpec weak_action;
  weak_action.effects.push_back(Effect{EffectKind::SET_LINK_OPERATIONAL, subject_of(weak), 1});
  weak_action.effects.push_back(Effect{EffectKind::SERVICE_REACHABLE_DELTA, subject_of(service), 1});
  weak_action.resource_uses.push_back(ResourceUse{spare, 1});
  weak_action.cost_units = 1;
  const ActionId weak_id = builder.add_action(weak_action);
  ActionSpec strong_action;
  strong_action.effects.push_back(Effect{EffectKind::SET_LINK_OPERATIONAL, subject_of(strong), 1});
  strong_action.effects.push_back(Effect{EffectKind::SERVICE_REACHABLE_DELTA, subject_of(service), 3});
  strong_action.resource_uses.push_back(ResourceUse{spare, 1});
  strong_action.cost_units = 50;
  const ActionId strong_id = builder.add_action(strong_action);
  builder.observe_link(strong, false);
  builder.observe_link(weak, false);
  builder.observe_node(n1, true);
  builder.observe_node(n2, true);
  builder.observe_service(service, 0);
  builder.observe_resource_available(spare, 1);
  GoalSpec goal;
  goal.kind = GoalKind::SERVICE_REACHABLE_AT_LEAST;
  goal.subject = subject_of(service);
  goal.value = 3;
  builder.add_goal(goal);
  const PlanRequest request = FabricBuilder::with_policy(builder.build(), permissive());
  Planner planner;
  const PlanningResult result = planner.plan(request);
  NRP_REQUIRE(result.plan.has_value());
  NRP_CHECK_EQ(result.plan->steps.size(), static_cast<std::size_t>(1));
  NRP_CHECK_EQ(result.plan->steps[0].action, strong_id);
  NRP_CHECK(weak_id != strong_id);
  NRP_CHECK(validate_plan(request, *result.plan).valid);
}
