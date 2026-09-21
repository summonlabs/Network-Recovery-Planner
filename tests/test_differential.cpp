// Network Recovery Planner - seeded differential testing against the reference.
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

struct Tally {
  std::uint64_t cases = 0;
  std::uint64_t completed = 0;
  std::uint64_t plans = 0;
  std::uint64_t infeasible = 0;
  std::uint64_t indeterminate = 0;
};

Tally run_seed(std::uint64_t seed, std::uint32_t cases, std::uint64_t max_plan_steps = 5) {
  Tally tally;
  Planner planner;
  ReferenceLimits limits;
  limits.max_plan_steps = max_plan_steps;
  limits.max_sequences = 4000000;
  for (std::uint32_t index = 0; index < cases; ++index) {
    const PlanRequest request = random_scenario(seed, index, max_plan_steps);
    const PlanningResult result = planner.plan(request);
    const ReferenceOutcome reference = reference_solve(request, limits);
    ++tally.cases;
    if (reference.kind == ReferenceOutcome::Kind::LIMIT_REACHED) continue;
    ++tally.completed;
    if (reference.plan_found) {
      ++tally.plans;
      NRP_CHECK_MSG(result.decision == PlanDecision::PLAN_FOUND,
                    "seed " << seed << " case " << index << " reference found a plan but the "
                            << "planner decided " << to_string(result.decision));
      if (!result.plan.has_value()) continue;
      NRP_CHECK_MSG(compare_objective(result.plan->objective, reference.objective) == 0,
                    "seed " << seed << " case " << index << " objective "
                            << result.plan->objective.to_string() << " != reference "
                            << reference.objective.to_string());
      NRP_CHECK_MSG(compare_encoding(result.plan->encoding(), reference.encoding) == 0,
                    "seed " << seed << " case " << index << " encoding differs from reference");
      const ValidationReport report = validate_plan(request, *result.plan);
      NRP_CHECK_MSG(report.valid, "seed " << seed << " case " << index << " plan invalid: "
                                          << report.render());
    } else {
      if (result.decision == PlanDecision::PLAN_FOUND) {
        NRP_CHECK_MSG(false, "seed " << seed << " case " << index
                                     << " planner found a plan the reference rejects");
        continue;
      }
      if (result.decision == PlanDecision::PROVEN_INFEASIBLE) {
        ++tally.infeasible;
      } else {
        ++tally.indeterminate;
        NRP_CHECK_MSG(result.stats.budget_exhausted,
                      "seed " << seed << " case " << index
                              << " indeterminate without budget exhaustion");
      }
    }
  }
  return tally;
}

}  // namespace

NRP_TEST(differential, thousands_of_seeded_cases_match_the_reference_solver) {
  Tally total;
  const std::uint64_t seeds[] = {1, 2, 3};
  for (const std::uint64_t seed : seeds) {
    const Tally tally = run_seed(seed, 1000);
    total.cases += tally.cases;
    total.completed += tally.completed;
    total.plans += tally.plans;
    total.infeasible += tally.infeasible;
    total.indeterminate += tally.indeterminate;
  }
  std::printf("  differential: cases=%llu completed=%llu plans=%llu infeasible=%llu indeterminate=%llu\n",
              static_cast<unsigned long long>(total.cases),
              static_cast<unsigned long long>(total.completed),
              static_cast<unsigned long long>(total.plans),
              static_cast<unsigned long long>(total.infeasible),
              static_cast<unsigned long long>(total.indeterminate));
  NRP_CHECK(total.cases >= 3000);
  NRP_CHECK(total.completed >= 2000);
  NRP_CHECK(total.plans > 0);
  NRP_CHECK(total.infeasible > 0);
  NRP_CHECK_EQ(total.indeterminate, 0ull);
}

NRP_TEST(differential, deeper_instances_match_the_reference_solver) {
  const Tally tally = run_seed(4242, 250, 6);
  std::printf("  differential(deep): cases=%llu completed=%llu plans=%llu infeasible=%llu\n",
              static_cast<unsigned long long>(tally.cases),
              static_cast<unsigned long long>(tally.completed),
              static_cast<unsigned long long>(tally.plans),
              static_cast<unsigned long long>(tally.infeasible));
  NRP_CHECK(tally.cases >= 250);
}

NRP_TEST(differential, planner_is_invariant_under_input_permutation) {
  Planner planner;
  for (std::uint32_t index = 0; index < 120; ++index) {
    const PlanRequest request = random_scenario(77, index, 5);
    const PlanningResult baseline = planner.plan(request);
    for (std::uint64_t seed = 1; seed <= 3; ++seed) {
      const PlanRequest permuted = permuted_request(request, seed * 31 + index);
      const PlanningResult other = planner.plan(permuted);
      NRP_CHECK_MSG(other.decision == baseline.decision,
                    "case " << index << " seed " << seed << " decision changed under permutation");
      NRP_CHECK_MSG(other.request_digest == baseline.request_digest,
                    "case " << index << " seed " << seed << " request digest changed");
      if (baseline.plan.has_value() && other.plan.has_value()) {
        NRP_CHECK_MSG(other.plan->plan_digest == baseline.plan->plan_digest,
                      "case " << index << " seed " << seed << " plan digest changed");
      }
      if (baseline.certificate.has_value() && other.certificate.has_value()) {
        NRP_CHECK_MSG(baseline.certificate->kind == other.certificate->kind,
                      "case " << index << " seed " << seed << " proof kind changed");
      }
    }
  }
}
