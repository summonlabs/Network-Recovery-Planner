// Network Recovery Planner - authority, evidence and model validation tests.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "nrp/planner.hpp"
#include "support/fixture.hpp"
#include "support/test_support.hpp"

using namespace nrp;
using namespace nrp::test;

NRP_TEST(authority, binding_states_are_distinguished) {
  AuthorityBinding binding;
  binding.authority = AuthorityId::from_value(1);
  binding.required = Generation{5};
  binding.granted = Generation{5};
  binding.level = AuthorityLevel::AUTHORIZATION;
  NRP_CHECK_EQ(static_cast<int>(binding.evaluate()), static_cast<int>(BindingState::CURRENT));

  binding.granted = Generation{4};
  NRP_CHECK_EQ(static_cast<int>(binding.evaluate()), static_cast<int>(BindingState::STALE));

  binding.granted = Generation{6};
  NRP_CHECK_EQ(static_cast<int>(binding.evaluate()), static_cast<int>(BindingState::INVALID));

  binding.granted = Generation{5};
  binding.authority = AuthorityId{};
  NRP_CHECK_EQ(static_cast<int>(binding.evaluate()), static_cast<int>(BindingState::UNKNOWN));

  binding.authority = AuthorityId::from_value(1);
  binding.level = AuthorityLevel::NONE;
  NRP_CHECK_EQ(static_cast<int>(binding.evaluate()), static_cast<int>(BindingState::UNKNOWN));

  AuthorityVector vector;
  NRP_CHECK_EQ(static_cast<int>(evaluate_domain(vector, AuthorityDomain::POLICY)),
               static_cast<int>(BindingState::UNKNOWN));
  NRP_CHECK(vector.all_current());  // vacuous: an empty vector grants nothing
  AuthorityBinding policy = binding;
  policy.domain = AuthorityDomain::POLICY;
  policy.level = AuthorityLevel::AUTHORIZATION;
  vector.bindings.push_back(policy);
  NRP_CHECK_EQ(static_cast<int>(evaluate_domain(vector, AuthorityDomain::POLICY)),
               static_cast<int>(BindingState::CURRENT));
  NRP_CHECK(vector.all_current());
  vector.bindings.push_back(policy);
  NRP_CHECK_EQ(static_cast<int>(evaluate_domain(vector, AuthorityDomain::POLICY)),
               static_cast<int>(BindingState::CONFLICT));
  NRP_CHECK(!vector.all_current());
  AuthorityBinding stale = binding;
  stale.domain = AuthorityDomain::FABRIC_STATE;
  stale.granted = Generation{1};
  AuthorityVector stale_vector;
  stale_vector.bindings.push_back(stale);
  NRP_CHECK(!stale_vector.all_current());
  NRP_CHECK_EQ(static_cast<int>(evaluate_domain(stale_vector, AuthorityDomain::FABRIC_STATE)),
               static_cast<int>(BindingState::STALE));
}

NRP_TEST(evidence, reconciliation_classifies_every_failure_mode) {
  FabricBuilder builder;
  const NodeId n1 = builder.add_node();
  const NodeId n2 = builder.add_node();
  const LinkId good = builder.add_link(n1, n2);
  const LinkId stale = builder.add_link(n1, n2);
  const LinkId ahead = builder.add_link(n1, n2);
  const LinkId conflicting = builder.add_link(n1, n2);
  const LinkId unsupported = builder.add_link(n1, n2);
  const LinkId dangling = builder.add_link(n1, n2);
  const LinkId invalid_value = builder.add_link(n1, n2);

  builder.observe_link(good, true);
  builder.observe_link(stale, true, kGeneration - 1);
  builder.observe_link(ahead, true, kGeneration + 1);
  builder.observe(EvidenceKind::LINK_OPERATIONAL, subject_of(conflicting), 1);
  builder.observe(EvidenceKind::LINK_OPERATIONAL, subject_of(conflicting), 0);
  builder.observe(EvidenceKind::LINK_OPERATIONAL, subject_of(unsupported), 1, kGeneration,
                  kEvidenceSequenceBase, TrustLabel::UNSUPPORTED);
  builder.observe(EvidenceKind::LINK_OPERATIONAL, subject_of(invalid_value), 7);

  PlanRequest request = builder.build();
  for (const NodeId node : {n1, n2}) builder.observe_node(node, true);
  DerivedState derived;
  const Status status = derive_initial_state(request.definition, request.evidence, request.authority,
                                             default_model_limits(), &derived);
  NRP_REQUIRE(status.ok());
  NRP_CHECK(derived.state.link_known[0] == 1);
  NRP_CHECK(derived.state.link_operational[0] == 1);
  for (std::size_t index = 1; index < 7; ++index) {
    NRP_CHECK_MSG(derived.state.link_known[index] == 0, "link " << index << " should be UNKNOWN");
  }
  NRP_CHECK(dangling == dangling);
  NRP_CHECK(!derived.unresolved.empty());
}

NRP_TEST(evidence, newest_sequence_wins_and_ties_conflict) {
  FabricBuilder builder;
  const NodeId n1 = builder.add_node();
  const NodeId n2 = builder.add_node();
  const LinkId link = builder.add_link(n1, n2);
  builder.observe(EvidenceKind::LINK_OPERATIONAL, subject_of(link), 0, kGeneration, 5);
  builder.observe(EvidenceKind::LINK_OPERATIONAL, subject_of(link), 1, kGeneration, 9);
  const PlanRequest request = builder.build();
  DerivedState derived;
  NRP_REQUIRE(derive_initial_state(request.definition, request.evidence, request.authority,
                                   default_model_limits(), &derived)
                  .ok());
  NRP_CHECK_EQ(static_cast<int>(derived.state.link_operational[0]), 1);
  NRP_CHECK(derived.unresolved.empty());

  FabricBuilder conflicting;
  const NodeId a = conflicting.add_node();
  const NodeId b = conflicting.add_node();
  const LinkId disputed = conflicting.add_link(a, b);
  conflicting.observe(EvidenceKind::LINK_OPERATIONAL, subject_of(disputed), 0, kGeneration, 4);
  conflicting.observe(EvidenceKind::LINK_OPERATIONAL, subject_of(disputed), 1, kGeneration, 4);
  const PlanRequest disputed_request = conflicting.build();
  DerivedState disputed_state;
  NRP_REQUIRE(derive_initial_state(disputed_request.definition, disputed_request.evidence,
                                   disputed_request.authority, default_model_limits(),
                                   &disputed_state)
                  .ok());
  NRP_CHECK_EQ(disputed_state.state.link_known[0], static_cast<std::uint8_t>(0));
  NRP_CHECK_EQ(disputed_state.unresolved.size(), static_cast<std::size_t>(1));
  bool conflict_explained = false;
  for (const Explanation& explanation : disputed_state.explanations) {
    if (explanation.code == ReasonCode::EVIDENCE_SUBJECT_CONFLICTING) conflict_explained = true;
  }
  NRP_CHECK(conflict_explained);
}

NRP_TEST(evidence, unknown_values_never_satisfy_preconditions) {
  FabricBuilder builder;
  const NodeId n1 = builder.add_node();
  const NodeId n2 = builder.add_node();
  const LinkId link = builder.add_link(n1, n2);
  ActionSpec spec;
  spec.preconditions.push_back(
      Precondition{PreconditionKind::LINK_NOT_OPERATIONAL, subject_of(link), 0});
  spec.effects.push_back(Effect{EffectKind::SET_LINK_OPERATIONAL, subject_of(link), 1});
  builder.add_action(spec);
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
  NRP_CHECK_EQ(std::string(to_string(result.decision)),
               std::string("INDETERMINATE_INCOMPLETE_EVIDENCE"));
  NRP_CHECK(!result.plan.has_value());
}

NRP_TEST(model, definition_validation_covers_every_reference) {
  {
    FabricBuilder builder;
    const NodeId n1 = builder.add_node();
    const NodeId n2 = builder.add_node();
    const LinkId link = builder.add_link(n1, n2);
    const ServiceId service = builder.add_service(3, 3, 2, true);
    (void)service;
    ActionSpec spec;
    spec.effects.push_back(Effect{EffectKind::SET_LINK_OPERATIONAL, subject_of(link), 1});
    builder.add_action(spec);
    PlanRequest request = builder.build();
    ExplanationLog log(8);
    NRP_CHECK(!validate_definition(request.definition, default_model_limits(), &log).ok());
  }
  {
    FabricBuilder builder;
    const NodeId n1 = builder.add_node();
    (void)n1;
    ActionSpec spec;
    spec.required_domain = static_cast<AuthorityDomain>(9);
    builder.add_action(spec);
    PlanRequest request = builder.build();
    ExplanationLog log(8);
    NRP_CHECK(!validate_definition(request.definition, default_model_limits(), &log).ok());
  }
  {
    FabricBuilder builder;
    const NodeId n1 = builder.add_node();
    (void)n1;
    ActionSpec spec;
    spec.max_occurrences = 0;
    builder.add_action(spec);
    PlanRequest request = builder.build();
    ExplanationLog log(8);
    NRP_CHECK(!validate_definition(request.definition, default_model_limits(), &log).ok());
  }
  {
    FabricBuilder builder;
    const NodeId n1 = builder.add_node();
    (void)n1;
    const ResourceId resource = builder.add_resource(ResourceKind::CONSUMABLE, 1, 0);
    ActionSpec spec;
    spec.resource_uses.push_back(ResourceUse{resource, 2});
    builder.add_action(spec);
    PlanRequest request = builder.build();
    ExplanationLog log(8);
    NRP_CHECK(!validate_definition(request.definition, default_model_limits(), &log).ok());
  }
  {
    FabricBuilder builder;
    const NodeId n1 = builder.add_node();
    (void)n1;
    ActionSpec spec;
    const ActionId id = builder.add_action(spec);
    (void)id;
    PlanRequest request = builder.build();
    request.definition.actions[0].dependencies.push_back(ActionDependency{request.definition.actions[0].id, 1});
    ExplanationLog log(8);
    NRP_CHECK(!validate_definition(request.definition, default_model_limits(), &log).ok());
  }
}
