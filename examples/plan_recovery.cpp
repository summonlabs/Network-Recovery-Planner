// Network Recovery Planner - example: plan a recovery for a disrupted fabric.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// All inputs here are SYNTHETIC: a deterministic model of a disrupted fabric.
#include <cstdio>
#include <string>

#include "nrp/planner.hpp"
#include "nrp/validate.hpp"

using namespace nrp;

int main() {
  const Epoch epoch = Epoch::from_value(4);
  const BootId boot = BootId::from_value(11);

  FabricDefinition definition;
  EvidenceBundle evidence;
  evidence.coordinator_epoch = epoch;
  evidence.boot = boot;

  NodeSpec a; a.id = NodeId::from_value(1);
  NodeSpec b; b.id = NodeId::from_value(2);
  definition.nodes = {a, b};
  LinkSpec link; link.id = LinkId::from_value(1); link.endpoint_a = a.id; link.endpoint_b = b.id;
  definition.links = {link};
  ServiceSpec service; service.id = ServiceId::from_value(1);
  service.required_reachable = 0; service.target_reachable = 1; service.max_reachable = 1;
  definition.services = {service};

  ActionSpec repair;
  repair.id = ActionId::from_value(1);
  repair.name = "restore-link-1";
  repair.kind = ActionKind::RESTORE;
  repair.blast_radius = 1;
  repair.cost_units = 12;
  repair.duration_ticks = 4;
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
    fact.generation = Generation{2};
    fact.source_domain = domain;
    fact.source = AuthorityId::from_value(7);
    fact.label = TrustLabel::SYNTHETIC;
    fact.sequence = Sequence{1};
    evidence.facts.push_back(fact);
  };
  observe(EvidenceKind::LINK_OPERATIONAL, Subject{SubjectKind::LINK, 1}, 0,
          AuthorityDomain::FABRIC_STATE, 1);
  observe(EvidenceKind::NODE_OPERATIONAL, Subject{SubjectKind::NODE, 1}, 1,
          AuthorityDomain::FABRIC_STATE, 2);
  observe(EvidenceKind::NODE_OPERATIONAL, Subject{SubjectKind::NODE, 2}, 1,
          AuthorityDomain::FABRIC_STATE, 3);
  observe(EvidenceKind::SERVICE_REACHABLE_ENDPOINTS, Subject{SubjectKind::SERVICE, 1}, 0,
          AuthorityDomain::FABRIC_STATE, 4);

  AuthorityVector authority;
  authority.coordinator_epoch = epoch;
  authority.boot = boot;
  for (std::uint8_t domain = 0; domain < static_cast<std::uint8_t>(AuthorityDomain::COUNT);
       ++domain) {
    AuthorityBinding binding;
    binding.domain = static_cast<AuthorityDomain>(domain);
    binding.authority = AuthorityId::from_value(50 + domain);
    binding.required = Generation{2};
    binding.granted = Generation{2};
    binding.level = AuthorityLevel::AUTHORIZATION;
    authority.bindings.push_back(binding);
  }

  PlanRequest request;
  request.id = RequestId::from_value(1);
  request.coordinator_epoch = epoch;
  request.boot = boot;
  request.attempt = AttemptId::from_value(1);
  request.definition = definition;
  request.evidence = evidence;
  request.authority = authority;
  request.policy.allow_irreversible_actions = true;

  const Planner planner;
  const PlanningResult result = planner.plan(request);
  std::printf("decision: %s\n", to_string(result.decision));
  if (result.plan.has_value()) {
    std::fputs(result.plan->render().c_str(), stdout);
    const ValidationReport report = validate_plan(request, *result.plan);
    std::printf("independent validation: %s\n", report.valid ? "VALID" : "INVALID");
    if (!report.valid) std::fputs(report.render().c_str(), stdout);
    return report.valid ? 0 : 2;
  }
  if (result.certificate.has_value()) {
    std::printf("proof: %s with %llu assumptions\n", to_string(result.certificate->kind),
                static_cast<unsigned long long>(result.certificate->assumptions.size()));
  }
  return result.decision == PlanDecision::PROVEN_INFEASIBLE ? 3 : 4;
}
