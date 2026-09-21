// Network Recovery Planner - downstream consumer of the installed package.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// Build with:
//   cmake -S . -B build -DCMAKE_PREFIX_PATH=<install prefix>
//   cmake --build build
//   ./build/nrp_consumer
#include <cstdio>
#include <string>

#include "nrp/planner.hpp"
#include "nrp/validate.hpp"
#include "nrp/version.hpp"

using namespace nrp;

int main() {
  std::printf("linked against Network Recovery Planner %s\n", version_string_with_build().c_str());

  const Epoch epoch = Epoch::from_value(9);
  const BootId boot = BootId::from_value(3);

  FabricDefinition definition;
  EvidenceBundle evidence;
  evidence.coordinator_epoch = epoch;
  evidence.boot = boot;

  NodeSpec node; node.id = NodeId::from_value(1);
  definition.nodes = {node};
  LinkSpec link; link.id = LinkId::from_value(1);
  link.endpoint_a = node.id; link.endpoint_b = node.id;
  definition.links = {link};
  ServiceSpec service; service.id = ServiceId::from_value(1);
  service.required_reachable = 0; service.target_reachable = 1; service.max_reachable = 1;
  definition.services = {service};

  ActionSpec repair;
  repair.id = ActionId::from_value(1);
  repair.name = "restore";
  repair.required_domain = AuthorityDomain::RECOVERY_ADMISSION;
  repair.required_level = AuthorityLevel::AUTHORIZATION;
  repair.preconditions.push_back(
      Precondition{PreconditionKind::LINK_NOT_OPERATIONAL, Subject{SubjectKind::LINK, 1}, 0});
  repair.effects.push_back(Effect{EffectKind::SET_LINK_OPERATIONAL, Subject{SubjectKind::LINK, 1}, 1});
  repair.effects.push_back(
      Effect{EffectKind::SERVICE_REACHABLE_DELTA, Subject{SubjectKind::SERVICE, 1}, 1});
  definition.actions = {repair};

  GoalSpec goal;
  goal.kind = GoalKind::SERVICE_REACHABLE_AT_LEAST;
  goal.subject = Subject{SubjectKind::SERVICE, 1};
  goal.value = 1;
  definition.goals = {goal};

  const auto observe = [&evidence](EvidenceKind kind, Subject subject, std::uint64_t value,
                                   AuthorityDomain domain, std::uint64_t id) {
    EvidenceFact fact;
    fact.id = EvidenceId::from_value(id);
    fact.kind = kind;
    fact.subject = subject;
    fact.value = value;
    fact.generation = Generation{5};
    fact.source_domain = domain;
    fact.source = AuthorityId::from_value(4);
    fact.label = TrustLabel::SYNTHETIC;
    fact.sequence = Sequence{1};
    evidence.facts.push_back(fact);
  };
  observe(EvidenceKind::LINK_OPERATIONAL, Subject{SubjectKind::LINK, 1}, 0,
          AuthorityDomain::FABRIC_STATE, 1);
  observe(EvidenceKind::SERVICE_REACHABLE_ENDPOINTS, Subject{SubjectKind::SERVICE, 1}, 0,
          AuthorityDomain::FABRIC_STATE, 2);

  AuthorityVector authority;
  authority.coordinator_epoch = epoch;
  authority.boot = boot;
  for (std::uint8_t domain = 0; domain < static_cast<std::uint8_t>(AuthorityDomain::COUNT);
       ++domain) {
    AuthorityBinding binding;
    binding.domain = static_cast<AuthorityDomain>(domain);
    binding.authority = AuthorityId::from_value(20 + domain);
    binding.required = Generation{5};
    binding.granted = Generation{5};
    binding.level = AuthorityLevel::AUTHORIZATION;
    authority.bindings.push_back(binding);
  }

  PlanRequest request;
  request.id = RequestId::from_value(11);
  request.coordinator_epoch = epoch;
  request.boot = boot;
  request.attempt = AttemptId::from_value(1);
  request.definition = definition;
  request.evidence = evidence;
  request.authority = authority;
  request.policy.allow_irreversible_actions = true;

  const Planner planner;
  const PlanningResult result = planner.plan(request);
  if (result.decision != PlanDecision::PLAN_FOUND || !result.plan.has_value()) {
    std::fprintf(stderr, "consumer: expected a plan, decision=%s\n", to_string(result.decision));
    return 1;
  }
  const ValidationReport report = validate_plan(request, *result.plan);
  std::printf("plan objective %s steps=%zu validated=%s\n",
              result.plan->objective.to_string().c_str(), result.plan->steps.size(),
              report.valid ? "yes" : "no");
  if (!report.valid) {
    std::fputs(report.render().c_str(), stderr);
    return 1;
  }
  return 0;
}
