// Network Recovery Planner - planner decision and outcome tests.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include <string>

#include "nrp/planner.hpp"
#include "nrp/validate.hpp"
#include "support/fixture.hpp"
#include "support/test_support.hpp"

using namespace nrp;
using namespace nrp::test;

namespace {

PlanPolicy permissive_policy(std::uint64_t steps = 6) {
  PlanPolicy policy;
  policy.allow_irreversible_actions = true;
  policy.max_plan_steps = steps;
  return policy;
}

}  // namespace

NRP_TEST(planner, finds_optimal_plan_and_validates) {
  TeachingFabric fabric;
  const PlanRequest request = fabric.request();
  Planner planner;
  const PlanningResult result = planner.plan(request);
  NRP_CHECK_EQ(std::string(to_string(result.decision)), std::string("PLAN_FOUND"));
  NRP_REQUIRE(result.plan.has_value());
  const RecoveryPlan& plan = *result.plan;
  NRP_CHECK_EQ(plan.steps.size(), static_cast<std::size_t>(2));
  NRP_CHECK_EQ(plan.steps[0].action, fabric.a1);
  NRP_CHECK_EQ(plan.steps[1].action, fabric.a2);
  NRP_CHECK_EQ(plan.objective[3], 3ull);
  NRP_CHECK_EQ(plan.objective[4], 2ull);
  NRP_CHECK_EQ(plan.objective[5], 3ull);
  NRP_CHECK_EQ(plan.objective[6], 30ull);
  NRP_CHECK_EQ(plan.objective[7], 12ull);
  NRP_CHECK_EQ(plan.steps[0].start_tick, 0ull);
  NRP_CHECK_EQ(plan.steps[0].end_tick, 5ull);
  NRP_CHECK_EQ(plan.steps[1].start_tick, 5ull);
  NRP_CHECK_EQ(plan.steps[1].end_tick, 12ull);
  NRP_CHECK_EQ(static_cast<int>(plan.steps[0].issued_level),
               static_cast<int>(AuthorityLevel::RECOMMENDATION));
  NRP_CHECK(!plan.steps[0].evidence.empty());

  const ValidationReport report = validate_plan(request, plan);
  NRP_CHECK_MSG(report.valid, report.render());
  NRP_CHECK(report.objective_matches);
  NRP_CHECK(report.digest_matches);
}

NRP_TEST(planner, already_satisfied_goals_yield_the_empty_plan) {
  FabricBuilder builder;
  const NodeId n1 = builder.add_node();
  const NodeId n2 = builder.add_node();
  const LinkId link = builder.add_link(n1, n2);
  ActionSpec spec;
  spec.kind = ActionKind::ISOLATE;
  spec.effects.push_back(Effect{EffectKind::SET_LINK_OPERATIONAL, subject_of(link), 0});
  builder.add_action(spec);
  builder.observe_link(link, true);
  builder.observe_node(n1, true);
  builder.observe_node(n2, true);
  GoalSpec goal;
  goal.kind = GoalKind::LINK_OPERATIONAL;
  goal.subject = subject_of(link);
  goal.value = 1;
  builder.add_goal(goal);
  const PlanRequest request = builder.build();
  Planner planner;
  const PlanningResult result = planner.plan(request);
  NRP_REQUIRE(result.plan.has_value());
  NRP_CHECK_EQ(result.plan->steps.size(), static_cast<std::size_t>(0));
  NRP_CHECK(validate_plan(request, *result.plan).valid);
}

NRP_TEST(planner, proves_an_unreachable_goal) {
  TeachingFabric fabric;
  FabricBuilder builder = fabric.builder;
  // A third link that is down and that no action in the definition can restore.
  const LinkId orphan = builder.add_link(fabric.n1, fabric.n2);
  builder.observe_link(orphan, false);
  GoalSpec goal;
  goal.kind = GoalKind::LINK_OPERATIONAL;
  goal.subject = subject_of(orphan);
  goal.value = 1;
  builder.add_goal(goal);
  const PlanRequest request =
      FabricBuilder::with_policy(builder.build(), permissive_policy());
  Planner planner;
  const PlanningResult result = planner.plan(request);
  NRP_CHECK_EQ(std::string(to_string(result.decision)), std::string("PROVEN_INFEASIBLE"));
  NRP_REQUIRE(result.certificate.has_value());
  NRP_CHECK_EQ(static_cast<int>(result.certificate->kind),
               static_cast<int>(ProofKind::GOAL_UPPER_BOUND));
  NRP_CHECK_EQ(result.certificate->unreachable_subject, subject_of(orphan));
  NRP_CHECK_EQ(result.certificate->unreachable_value, 0ull);
  NRP_CHECK_EQ(result.certificate->required_value, 1ull);
  NRP_CHECK(validate_certificate(request, *result.certificate).valid);
  NRP_CHECK(!result.plan.has_value());
}

NRP_TEST(planner, proves_a_dependency_cycle) {
  FabricBuilder builder;
  const NodeId n1 = builder.add_node();
  const NodeId n2 = builder.add_node();
  const LinkId link = builder.add_link(n1, n2);
  ActionSpec first;
  first.effects.push_back(Effect{EffectKind::SET_LINK_OPERATIONAL, subject_of(link), 1});
  const ActionId first_id = builder.add_action(first);
  ActionSpec second;
  second.effects.push_back(Effect{EffectKind::SET_LINK_OPERATIONAL, subject_of(link), 1});
  const ActionId second_id = builder.add_action(second);
  {
    PlanRequest request = builder.build();
    request.definition.actions[0].dependencies.push_back(ActionDependency{second_id, 1});
    request.definition.actions[1].dependencies.push_back(ActionDependency{first_id, 1});
    request.definition.canonicalise();
    Planner planner;
    const PlanningResult result = planner.plan(request);
    NRP_CHECK_EQ(std::string(to_string(result.decision)), std::string("PROVEN_INFEASIBLE"));
    NRP_REQUIRE(result.certificate.has_value());
    NRP_CHECK_EQ(static_cast<int>(result.certificate->kind),
                 static_cast<int>(ProofKind::DEPENDENCY_CYCLE));
    NRP_CHECK(result.certificate->cycle.size() >= 2);
    NRP_CHECK(validate_certificate(request, *result.certificate).valid);
  }
}

NRP_TEST(planner, budget_exhaustion_is_indeterminate_not_infeasible) {
  TeachingFabric fabric;
  PlanPolicy policy = permissive_policy();
  policy.max_nodes_expanded = 1;
  const PlanRequest request = FabricBuilder::with_policy(fabric.request(), policy);
  Planner planner;
  const PlanningResult result = planner.plan(request);
  NRP_CHECK_EQ(std::string(to_string(result.decision)),
               std::string("INDETERMINATE_SEARCH_LIMIT"));
  NRP_CHECK(result.stats.budget_exhausted);
  NRP_CHECK(!result.plan.has_value());
  NRP_CHECK(!result.certificate.has_value());
}

NRP_TEST(planner, incomplete_evidence_blocks_infeasibility_claims) {
  TeachingFabric fabric;
  FabricBuilder builder = fabric.builder;
  EvidenceBundle evidence = builder.evidence();
  EvidenceBundle filtered;
  filtered.coordinator_epoch = evidence.coordinator_epoch;
  filtered.boot = evidence.boot;
  for (const EvidenceFact& fact : evidence.facts) {
    // The service reachability is what the goal depends on, so removing it makes
    // the goal unverifiable rather than false.
    if (fact.kind == EvidenceKind::SERVICE_REACHABLE_ENDPOINTS &&
        fact.subject == subject_of(fabric.s1)) {
      continue;
    }
    filtered.facts.push_back(fact);
  }
  PlanRequest request = builder.build();
  request.evidence = filtered;
  request.evidence.canonicalise();
  Planner planner;
  const PlanningResult result = planner.plan(request);
  NRP_CHECK_EQ(std::string(to_string(result.decision)),
               std::string("INDETERMINATE_INCOMPLETE_EVIDENCE"));
  NRP_CHECK(!result.certificate.has_value());
  NRP_CHECK(!result.unresolved_subjects.empty());
}

NRP_TEST(planner, stale_authority_is_refused) {
  TeachingFabric fabric;
  PlanRequest request = fabric.request();
  for (AuthorityBinding& binding : request.authority.bindings) {
    binding.granted = Generation{1};
    binding.required = Generation{2};
  }
  request.authority.canonicalise();
  Planner planner;
  const PlanningResult result = planner.plan(request);
  NRP_CHECK_EQ(std::string(to_string(result.decision)),
               std::string("REJECTED_STALE_AUTHORITY"));
}

NRP_TEST(planner, absent_authority_domain_is_refused) {
  TeachingFabric fabric;
  PlanRequest request = fabric.request();
  std::vector<AuthorityBinding> kept;
  for (const AuthorityBinding& binding : request.authority.bindings) {
    if (binding.domain == AuthorityDomain::POLICY) continue;
    kept.push_back(binding);
  }
  request.authority.bindings = kept;
  request.authority.canonicalise();
  Planner planner;
  const PlanningResult result = planner.plan(request);
  NRP_CHECK_EQ(std::string(to_string(result.decision)),
               std::string("REJECTED_UNKNOWN_AUTHORITY"));
}

NRP_TEST(planner, contradictory_authority_is_refused) {
  TeachingFabric fabric;
  PlanRequest request = fabric.request();
  AuthorityBinding duplicate = request.authority.bindings.front();
  duplicate.authority = AuthorityId::from_value(777);
  request.authority.bindings.push_back(duplicate);
  request.authority.canonicalise();
  Planner planner;
  const PlanningResult result = planner.plan(request);
  NRP_CHECK_EQ(std::string(to_string(result.decision)),
               std::string("REJECTED_CONFLICTING_AUTHORITY"));
}

NRP_TEST(planner, insufficient_authority_level_is_refused) {
  TeachingFabric fabric;
  PlanRequest request = fabric.request();
  for (AuthorityBinding& binding : request.authority.bindings) {
    binding.level = AuthorityLevel::ELIGIBILITY;
  }
  Planner planner;
  const PlanningResult result = planner.plan(request);
  NRP_CHECK_EQ(std::string(to_string(result.decision)),
               std::string("REJECTED_UNKNOWN_AUTHORITY"));
}

NRP_TEST(planner, a_later_epoch_fence_revokes_the_request) {
  TeachingFabric fabric;
  PlanRequest request = fabric.request();
  Fence fence;
  fence.epoch = Epoch::from_value(request.coordinator_epoch.value() + 1);
  fence.boot = request.boot;
  fence.domain = AuthorityDomain::FABRIC_STATE;
  fence.minimum_generation = Generation{99};
  fence.sequence = Sequence{5};
  fence.reason = "failover";
  request.fences.push_back(fence);
  Planner planner;
  const PlanningResult result = planner.plan(request);
  NRP_CHECK_EQ(std::string(to_string(result.decision)), std::string("REJECTED_FENCED"));
}

NRP_TEST(planner, policy_can_exclude_irreversible_actions) {
  TeachingFabric fabric;
  PlanPolicy policy;
  policy.allow_irreversible_actions = false;
  policy.max_plan_steps = 6;
  const PlanRequest request = FabricBuilder::with_policy(fabric.request(), policy);
  Planner planner;
  const PlanningResult result = planner.plan(request);
  NRP_CHECK_EQ(std::string(to_string(result.decision)), std::string("PROVEN_INFEASIBLE"));
  NRP_REQUIRE(result.certificate.has_value());
  NRP_CHECK_EQ(static_cast<int>(result.certificate->kind),
               static_cast<int>(ProofKind::EXHAUSTIVE_SEARCH));
  bool mentions_policy = false;
  for (const std::string& assumption : result.certificate->assumptions) {
    if (assumption.find("irreversible") != std::string::npos) mentions_policy = true;
  }
  NRP_CHECK(mentions_policy);
  NRP_CHECK(validate_certificate(request, *result.certificate).valid);
}

NRP_TEST(planner, scarce_consumable_resource_limits_the_plan) {
  TeachingFabric fabric;
  FabricBuilder builder = fabric.builder;
  PlanRequest request = builder.build();
  request.definition.resources[0].capacity = 1;
  for (EvidenceFact& fact : request.evidence.facts) {
    if (fact.kind == EvidenceKind::RESOURCE_AVAILABLE_UNITS) fact.value = 1;
  }
  request.definition.canonicalise();
  request.evidence.canonicalise();
  Planner planner;
  const PlanningResult result = planner.plan(request);
  NRP_CHECK_EQ(std::string(to_string(result.decision)), std::string("PROVEN_INFEASIBLE"));
  NRP_REQUIRE(result.certificate.has_value());
  NRP_CHECK_EQ(static_cast<int>(result.certificate->kind),
               static_cast<int>(ProofKind::EXHAUSTIVE_SEARCH));
}

NRP_TEST(planner, mutually_exclusive_actions_are_never_combined) {
  FabricBuilder builder;
  const NodeId n1 = builder.add_node();
  const NodeId n2 = builder.add_node();
  const LinkId link = builder.add_link(n1, n2);
  const ExclusionGroupId group = ExclusionGroupId::from_value(1);
  builder.add_exclusion_group(group, 1);
  ActionSpec first;
  first.effects.push_back(Effect{EffectKind::SET_LINK_OPERATIONAL, subject_of(link), 1});
  first.exclusion_groups.push_back(group);
  first.cost_units = 5;
  const ActionId first_id = builder.add_action(first);
  ActionSpec second;
  second.effects.push_back(Effect{EffectKind::SET_LINK_OPERATIONAL, subject_of(link), 1});
  second.exclusion_groups.push_back(group);
  second.cost_units = 1;
  const ActionId second_id = builder.add_action(second);
  builder.observe_link(link, false);
  builder.observe_node(n1, true);
  builder.observe_node(n2, true);
  GoalSpec goal;
  goal.kind = GoalKind::LINK_OPERATIONAL;
  goal.subject = subject_of(link);
  goal.value = 1;
  builder.add_goal(goal);
  const PlanRequest request = FabricBuilder::with_policy(builder.build(), permissive_policy());
  Planner planner;
  const PlanningResult result = planner.plan(request);
  NRP_REQUIRE(result.plan.has_value());
  NRP_CHECK_EQ(result.plan->steps.size(), static_cast<std::size_t>(1));
  NRP_CHECK_EQ(result.plan->steps[0].action, second_id);
  NRP_CHECK(first_id != second_id);
  NRP_CHECK(validate_plan(request, *result.plan).valid);
}

NRP_TEST(planner, reusable_resource_holds_overlap) {
  FabricBuilder builder;
  const NodeId n1 = builder.add_node();
  const NodeId n2 = builder.add_node();
  const ResourceId crew = builder.add_resource(ResourceKind::REUSABLE, 1, 2);
  const LinkId first_link = builder.add_link(n1, n2);
  const LinkId filler_link = builder.add_link(n1, n2);
  ActionSpec first;
  first.effects.push_back(Effect{EffectKind::SET_LINK_OPERATIONAL, subject_of(first_link), 1});
  first.resource_uses.push_back(ResourceUse{crew, 1});
  const ActionId first_id = builder.add_action(first);
  ActionSpec filler;
  filler.effects.push_back(Effect{EffectKind::SET_LINK_OPERATIONAL, subject_of(filler_link), 1});
  const ActionId filler_id = builder.add_action(filler);
  ActionSpec second;
  second.effects.push_back(Effect{EffectKind::SET_NODE_OPERATIONAL, subject_of(n1), 1});
  second.resource_uses.push_back(ResourceUse{crew, 1});
  const ActionId second_id = builder.add_action(second);
  builder.observe_link(first_link, false);
  builder.observe_link(filler_link, false);
  builder.observe_node(n1, false);
  builder.observe_node(n2, true);
  builder.observe_resource_available(crew, 1);
  GoalSpec goal;
  goal.kind = GoalKind::LINK_OPERATIONAL;
  goal.subject = subject_of(first_link);
  goal.value = 1;
  builder.add_goal(goal);
  GoalSpec node_goal;
  node_goal.kind = GoalKind::NODE_OPERATIONAL;
  node_goal.subject = subject_of(n1);
  node_goal.value = 1;
  builder.add_goal(node_goal);
  const PlanRequest request = FabricBuilder::with_policy(builder.build(), permissive_policy());
  Planner planner;
  const PlanningResult result = planner.plan(request);
  // The crew hold spans two steps, so the two crew steps cannot be adjacent and
  // the filler action is mandatory between them.
  NRP_REQUIRE(result.plan.has_value());
  NRP_CHECK_EQ(result.plan->steps.size(), static_cast<std::size_t>(3));
  NRP_CHECK_EQ(result.plan->steps[0].action, first_id);
  NRP_CHECK_EQ(result.plan->steps[1].action, filler_id);
  NRP_CHECK_EQ(result.plan->steps[2].action, second_id);
  NRP_CHECK(validate_plan(request, *result.plan).valid);
}

NRP_TEST(planner, deterministic_across_runs_and_permutations) {
  TeachingFabric fabric;
  const PlanRequest request = fabric.request();
  Planner planner;
  const PlanningResult first = planner.plan(request);
  const PlanningResult second = planner.plan(request);
  NRP_REQUIRE(first.plan.has_value());
  NRP_REQUIRE(second.plan.has_value());
  NRP_CHECK_EQ(first.plan->plan_digest, second.plan->plan_digest);
  NRP_CHECK_EQ(first.plan->id, second.plan->id);
  for (std::uint64_t seed = 1; seed <= 24; ++seed) {
    const PlanRequest permuted = permuted_request(request, seed);
    const PlanningResult other = planner.plan(permuted);
    NRP_REQUIRE(other.plan.has_value());
    NRP_CHECK_EQ(other.plan->plan_digest, first.plan->plan_digest);
  }
}
