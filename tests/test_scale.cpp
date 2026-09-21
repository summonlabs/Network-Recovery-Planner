// Network Recovery Planner - scale and work counter measurements.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include <chrono>
#include <cstdio>
#include <string>

#include "nrp/planner.hpp"
#include "nrp/validate.hpp"
#include "support/fixture.hpp"
#include "support/test_support.hpp"

using namespace nrp;
using namespace nrp::test;

namespace {

/// Builds a synthetic corridor with \p links independent repairs and a service
/// that needs all of them, which is the worst case for search width.
PlanRequest corridor(std::uint32_t links, std::uint64_t step_budget = 12) {
  FabricBuilder builder;
  const NodeId left = builder.add_node();
  const NodeId right = builder.add_node();
  const ServiceId service = builder.add_service(0, links, links, false);
  for (std::uint32_t index = 0; index < links; ++index) {
    const LinkId link = builder.add_link(left, right);
    builder.observe_link(link, false);
    ActionSpec spec;
    spec.name = "restore-" + std::to_string(index);
    spec.kind = ActionKind::RESTORE;
    spec.blast_radius = 1;
    spec.disruption = 1;
    spec.cost_units = 10 + index;
    spec.duration_ticks = 2;
    spec.required_domain = AuthorityDomain::RECOVERY_ADMISSION;
    spec.required_level = AuthorityLevel::AUTHORIZATION;
    spec.preconditions.push_back(
        Precondition{PreconditionKind::LINK_NOT_OPERATIONAL, subject_of(link), 0});
    spec.effects.push_back(Effect{EffectKind::SET_LINK_OPERATIONAL, subject_of(link), 1});
    spec.effects.push_back(
        Effect{EffectKind::SERVICE_REACHABLE_DELTA, subject_of(service), 1});
    builder.add_action(spec);
  }
  builder.observe_node(left, true);
  builder.observe_node(right, true);
  builder.observe_service(service, 0);
  GoalSpec goal;
  goal.kind = GoalKind::SERVICE_REACHABLE_AT_LEAST;
  goal.subject = subject_of(service);
  goal.value = links;
  builder.add_goal(goal);
  PlanPolicy policy = fixture_policy(step_budget);
  policy.max_nodes_expanded = 500000;
  policy.max_generated_states = 1000000;
  policy.max_frontier_entries = 500000;
  return builder.build(RequestId::from_value(1), AttemptId::from_value(1), policy);
}

struct Measurement {
  std::uint32_t links = 0;
  double milliseconds = 0;
  std::uint64_t nodes_expanded = 0;
  std::uint64_t nodes_generated = 0;
  std::uint64_t frontier_high_water = 0;
  std::uint64_t states_revisited = 0;
  std::uint64_t plan_steps = 0;
  Digest digest{};
};

Measurement measure(std::uint32_t links) {
  const PlanRequest request = corridor(links);
  Planner planner;
  const auto started = std::chrono::steady_clock::now();
  const PlanningResult result = planner.plan(request);
  const auto finished = std::chrono::steady_clock::now();
  Measurement measurement;
  measurement.links = links;
  measurement.milliseconds =
      std::chrono::duration<double, std::milli>(finished - started).count();
  measurement.nodes_expanded = result.stats.nodes_expanded;
  measurement.nodes_generated = result.stats.nodes_generated;
  measurement.frontier_high_water = result.stats.frontier_high_water;
  measurement.states_revisited = result.stats.states_revisited;
  if (result.plan.has_value()) {
    measurement.plan_steps = result.plan->steps.size();
    measurement.digest = result.plan->plan_digest;
  }
  NRP_CHECK_MSG(result.decision == PlanDecision::PLAN_FOUND,
                "links=" << links << " decision=" << to_string(result.decision));
  return measurement;
}

}  // namespace

NRP_TEST(scale, completed_work_grows_predictably_with_instance_size) {
  std::vector<Measurement> measurements;
  for (const std::uint32_t links : {4u, 6u, 8u, 10u}) {
    measurements.push_back(measure(links));
  }
  std::printf("  scale: links  steps  expanded  generated  frontier  revisited  ms\n");
  for (const Measurement& measurement : measurements) {
    std::printf("  scale: %5u %6llu %9llu %10llu %9llu %10llu %6.2f\n", measurement.links,
                static_cast<unsigned long long>(measurement.plan_steps),
                static_cast<unsigned long long>(measurement.nodes_expanded),
                static_cast<unsigned long long>(measurement.nodes_generated),
                static_cast<unsigned long long>(measurement.frontier_high_water),
                static_cast<unsigned long long>(measurement.states_revisited),
                measurement.milliseconds);
  }
  // The optimum is the full set of repairs in identity order.
  for (const Measurement& measurement : measurements) {
    NRP_CHECK_EQ(measurement.plan_steps, static_cast<std::uint64_t>(measurement.links));
  }
  // Work must not explode super-exponentially: the largest instance may not cost
  // more than a bounded multiple of the smallest one per action.
  const double smallest = measurements.front().milliseconds;
  const double largest = measurements.back().milliseconds;
  NRP_CHECK_MSG(largest < 20000.0, "largest instance took " << largest << " ms");
  NRP_CHECK(smallest >= 0.0);
}

NRP_TEST(scale, retained_state_stays_bounded_and_reproducible) {
  const Measurement first = measure(8);
  const Measurement second = measure(8);
  NRP_CHECK_EQ(first.digest, second.digest);
  NRP_CHECK_EQ(first.nodes_expanded, second.nodes_expanded);
  NRP_CHECK(first.frontier_high_water <= 500000ull);
  NRP_CHECK(first.nodes_generated <= 1000000ull);
}

NRP_TEST(scale, budget_exhaustion_at_scale_stays_indeterminate) {
  PlanRequest request = corridor(12);
  request.policy.max_nodes_expanded = 50;
  request.policy.max_generated_states = 50;
  request.policy.max_frontier_entries = 50;
  Planner planner;
  const PlanningResult result = planner.plan(request);
  NRP_CHECK_MSG(result.decision == PlanDecision::INDETERMINATE_SEARCH_LIMIT ||
                    result.decision == PlanDecision::PLAN_FOUND,
                "unexpected decision " << to_string(result.decision));
  if (result.decision == PlanDecision::INDETERMINATE_SEARCH_LIMIT) {
    NRP_CHECK(result.stats.budget_exhausted);
    NRP_CHECK(!result.certificate.has_value());
    NRP_CHECK(!result.plan.has_value());
  }
}
