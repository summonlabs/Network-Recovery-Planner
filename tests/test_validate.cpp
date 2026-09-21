// Network Recovery Planner - independent validation tests.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "nrp/validate.hpp"
#include "support/fixture.hpp"
#include "support/test_support.hpp"

using namespace nrp;
using namespace nrp::test;

namespace {

RecoveryPlan planned(const PlanRequest& request, PlanningResult* result) {
  Planner planner;
  *result = planner.plan(request);
  return result->plan.has_value() ? *result->plan : RecoveryPlan{};
}

}  // namespace

NRP_TEST(validate, accepts_a_genuine_plan) {
  TeachingFabric fabric;
  const PlanRequest request = fabric.request();
  PlanningResult result;
  const RecoveryPlan plan = planned(request, &result);
  NRP_REQUIRE(result.plan.has_value());
  const ValidationReport report = validate_plan(request, plan);
  NRP_CHECK_MSG(report.valid, report.render());
  NRP_CHECK(report.objective_matches);
  NRP_CHECK(report.digest_matches);
  NRP_CHECK_EQ(compare_objective(report.recomputed_objective, plan.objective), 0);
}

NRP_TEST(validate, rejects_a_reordered_plan) {
  TeachingFabric fabric;
  const PlanRequest request = fabric.request();
  PlanningResult result;
  RecoveryPlan plan = planned(request, &result);
  NRP_REQUIRE(plan.steps.size() >= 2);
  std::swap(plan.steps[0], plan.steps[1]);
  const ValidationReport report = validate_plan(request, plan);
  NRP_CHECK(!report.valid);
  NRP_CHECK(!report.findings.empty());
}

NRP_TEST(validate, rejects_a_plan_whose_precondition_is_contradicted_by_evidence) {
  TeachingFabric fabric;
  const PlanRequest request = fabric.request();
  PlanningResult result;
  RecoveryPlan plan = planned(request, &result);
  NRP_REQUIRE(!plan.steps.empty());
  // The same plan judged against evidence in which the first step's
  // precondition no longer holds: the validator must re-derive it and refuse.
  PlanRequest opposed = request;
  for (EvidenceFact& fact : opposed.evidence.facts) {
    if (fact.kind == EvidenceKind::LINK_OPERATIONAL && fact.subject == subject_of(fabric.l1)) {
      fact.value = 1;
    }
  }
  opposed.evidence.canonicalise();
  const ValidationReport report = validate_plan(opposed, plan);
  NRP_CHECK(!report.valid);
  bool saw_precondition = false;
  for (const ValidationFinding& finding : report.findings) {
    if (finding.code == ReasonCode::VALIDATION_PRECONDITION_UNMET) saw_precondition = true;
  }
  NRP_CHECK(saw_precondition);
}

NRP_TEST(validate, rejects_a_foreign_action) {
  TeachingFabric fabric;
  const PlanRequest request = fabric.request();
  PlanningResult result;
  RecoveryPlan plan = planned(request, &result);
  NRP_REQUIRE(!plan.steps.empty());
  plan.steps.back().action = ActionId::from_value(9999);
  const ValidationReport report = validate_plan(request, plan);
  NRP_CHECK(!report.valid);
}

NRP_TEST(validate, rejects_a_rebound_evidence_generation) {
  TeachingFabric fabric;
  const PlanRequest request = fabric.request();
  PlanningResult result;
  RecoveryPlan plan = planned(request, &result);
  NRP_REQUIRE(!plan.steps.empty());
  NRP_REQUIRE(!plan.steps[0].evidence.empty());
  plan.steps[0].evidence[0].generation = Generation{kGeneration + 5};
  const ValidationReport report = validate_plan(request, plan);
  NRP_CHECK(!report.valid);
  bool saw_binding = false;
  for (const ValidationFinding& finding : report.findings) {
    if (finding.code == ReasonCode::VALIDATION_EVIDENCE_BINDING_MISMATCH) saw_binding = true;
  }
  NRP_CHECK(saw_binding);
}

NRP_TEST(validate, rejects_a_rebound_authority_generation) {
  TeachingFabric fabric;
  const PlanRequest request = fabric.request();
  PlanningResult result;
  RecoveryPlan plan = planned(request, &result);
  NRP_REQUIRE(!plan.steps.empty());
  plan.steps[0].required_generation = Generation{kGeneration + 1};
  const ValidationReport report = validate_plan(request, plan);
  NRP_CHECK(!report.valid);
}

NRP_TEST(validate, rejects_an_overclaimed_authority_level) {
  TeachingFabric fabric;
  const PlanRequest request = fabric.request();
  PlanningResult result;
  RecoveryPlan plan = planned(request, &result);
  NRP_REQUIRE(!plan.steps.empty());
  plan.steps[0].issued_level = AuthorityLevel::AUTHORIZATION;
  const ValidationReport report = validate_plan(request, plan);
  NRP_CHECK(!report.valid);
}

NRP_TEST(validate, rejects_a_tampered_objective) {
  TeachingFabric fabric;
  const PlanRequest request = fabric.request();
  PlanningResult result;
  RecoveryPlan plan = planned(request, &result);
  plan.objective[4] += 1;
  const ValidationReport report = validate_plan(request, plan);
  NRP_CHECK(!report.valid);
  NRP_CHECK(!report.objective_matches);
}

NRP_TEST(validate, rejects_a_tampered_digest) {
  TeachingFabric fabric;
  const PlanRequest request = fabric.request();
  PlanningResult result;
  RecoveryPlan plan = planned(request, &result);
  plan.plan_digest.lo ^= 0xABCDEFull;
  const ValidationReport report = validate_plan(request, plan);
  NRP_CHECK(!report.valid);
  NRP_CHECK(!report.digest_matches);
}

NRP_TEST(validate, rejects_a_plan_bound_to_another_request) {
  TeachingFabric fabric;
  const PlanRequest request = fabric.request();
  PlanningResult result;
  RecoveryPlan plan = planned(request, &result);
  plan.request = RequestId::from_value(request.id.value() + 1);
  const ValidationReport report = validate_plan(request, plan);
  NRP_CHECK(!report.valid);
}

NRP_TEST(validate, rejects_an_extra_step_beyond_the_occurrence_bound) {
  TeachingFabric fabric;
  const PlanRequest request = fabric.request();
  PlanningResult result;
  RecoveryPlan plan = planned(request, &result);
  NRP_REQUIRE(plan.steps.size() == 2);
  PlanStep duplicate = plan.steps[0];
  duplicate.index = 2;
  duplicate.occurrence = 2;
  plan.steps.push_back(duplicate);
  const ValidationReport report = validate_plan(request, plan);
  NRP_CHECK(!report.valid);
}

NRP_TEST(validate, rejects_a_plan_that_ignores_an_exclusion_group) {
  TeachingFabric fabric;
  const PlanRequest request = fabric.request();
  PlanningResult result;
  RecoveryPlan plan = planned(request, &result);
  NRP_REQUIRE(plan.steps.size() == 2);
  PlanningResult second;
  RecoveryPlan other = planned(request, &second);
  other.steps.push_back(other.steps[0]);
  other.steps.back().index = 2;
  other.steps.back().occurrence = 2;
  const ValidationReport report = validate_plan(request, other);
  NRP_CHECK(!report.valid);
}

NRP_TEST(validate, rejects_a_fenced_plan) {
  TeachingFabric fabric;
  const PlanRequest request = fabric.request();
  PlanningResult result;
  RecoveryPlan plan = planned(request, &result);
  PlanRequest fenced = request;
  Fence fence;
  fence.epoch = Epoch::from_value(request.coordinator_epoch.value() + 1);
  fence.boot = request.boot;
  fence.domain = AuthorityDomain::FABRIC_STATE;
  fence.minimum_generation = Generation{1};
  fence.sequence = Sequence{3};
  fence.reason = "restart";
  fenced.fences.push_back(fence);
  const ValidationReport report = validate_plan(fenced, plan);
  NRP_CHECK(!report.valid);
}

NRP_TEST(validate, exhaustive_proof_with_unknown_evidence_is_invalid) {
  TeachingFabric fabric;
  FabricBuilder builder = fabric.builder;
  EvidenceBundle filtered;
  filtered.coordinator_epoch = builder.evidence().coordinator_epoch;
  filtered.boot = builder.evidence().boot;
  for (const EvidenceFact& fact : builder.evidence().facts) {
    if (fact.kind == EvidenceKind::LINK_OPERATIONAL || fact.kind == EvidenceKind::NODE_OPERATIONAL) {
      continue;
    }
    filtered.facts.push_back(fact);
  }
  PlanRequest request = builder.build();
  request.evidence = filtered;
  request.evidence.canonicalise();
  InfeasibilityCertificate certificate;
  certificate.kind = ProofKind::EXHAUSTIVE_SEARCH;
  certificate.request_digest = request.digest();
  certificate.policy_digest = request.policy.digest();
  certificate.nodes_expanded = 5;
  certificate.assumptions.push_back("assumed");
  const ValidationReport report = validate_certificate(request, certificate);
  NRP_CHECK(!report.valid);
}
