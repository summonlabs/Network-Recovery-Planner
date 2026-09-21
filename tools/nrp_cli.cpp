// Network Recovery Planner - command line tool.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "nrp/persistence.hpp"
#include "nrp/planner.hpp"
#include "nrp/reference_solver.hpp"
#include "nrp/validate.hpp"
#include "nrp/version.hpp"

namespace {

using namespace nrp;

const char* kUsage =
    "nrp-cli <command> [options]\n"
    "\n"
    "commands:\n"
    "  version                              print the runtime version\n"
    "  scenarios                            list the built-in synthetic scenarios\n"
    "  plan      [--scenario NAME] [--steps N]\n"
    "                                       plan a scenario and print the decision\n"
    "  validate  [--scenario NAME]\n"
    "                                       plan, then independently validate the plan\n"
    "  reference [--scenario NAME] [--steps N]\n"
    "                                       run the slow exact reference solver\n"
    "  store     --path PATH [--records N]\n"
    "                                       exercise the durable store and report recovery\n"
    "  selftest                             deterministic end-to-end check\n"
    "\n"
    "scenarios (all SYNTHETIC fixtures, no hardware is involved):\n"
    "  teaching      two-link three-node service restoration\n"
    "  unreachable   a goal no action can ever satisfy\n"
    "  cycle         a dependency cycle between two actions\n"
    "  stale         evidence from an older generation than the granted authority\n"
    "  partial       evidence missing for a link a step depends on\n"
    "  budget        a search budget too small to conclude anything\n"
    "  random:S:N    deterministic random instance for seed S and case N\n";

// The scenarios mirror the synthetic fixtures used by the test suites.
struct Scenario {
  PlanRequest request;
  const char* note = "";
};

PlanPolicy scenario_policy(std::uint64_t steps = 6) {
  PlanPolicy policy;
  policy.allow_irreversible_actions = true;
  policy.max_plan_steps = steps;
  return policy;
}

AuthorityVector authority_for(Epoch epoch, BootId boot, std::uint64_t generation) {
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
    binding.level = AuthorityLevel::AUTHORIZATION;
    authority.bindings.push_back(binding);
  }
  authority.canonicalise();
  return authority;
}

Scenario teaching(std::uint64_t steps) {
  const Epoch epoch = Epoch::from_value(1);
  const BootId boot = BootId::from_value(7);
  FabricDefinition definition;
  EvidenceBundle evidence;
  evidence.coordinator_epoch = epoch;
  evidence.boot = boot;

  NodeSpec n1; n1.id = NodeId::from_value(1);
  NodeSpec n2; n2.id = NodeId::from_value(2);
  NodeSpec n3; n3.id = NodeId::from_value(3); n3.protected_node = true;
  definition.nodes = {n1, n2, n3};
  LinkSpec l1; l1.id = LinkId::from_value(1); l1.endpoint_a = n1.id; l1.endpoint_b = n2.id;
  LinkSpec l2; l2.id = LinkId::from_value(2); l2.endpoint_a = n2.id; l2.endpoint_b = n3.id;
  definition.links = {l1, l2};
  ServiceSpec service; service.id = ServiceId::from_value(1); service.required_reachable = 1;
  service.target_reachable = 2; service.max_reachable = 2; service.protected_service = true;
  definition.services = {service};
  ResourceSpec spare; spare.id = ResourceId::from_value(1); spare.kind = ResourceKind::CONSUMABLE;
  spare.capacity = 2;
  definition.resources = {spare};

  const auto add = [&](const char* name, std::uint32_t blast, std::uint64_t cost,
                                 std::uint64_t duration, int delta, LinkId link) {
    ActionSpec spec;
    spec.name = name;
    spec.kind = ActionKind::RESTORE;
    spec.blast_radius = blast;
    spec.disruption = blast;
    spec.cost_units = cost;
    spec.duration_ticks = duration;
    spec.required_domain = AuthorityDomain::RECOVERY_ADMISSION;
    spec.required_level = AuthorityLevel::AUTHORIZATION;
    spec.preconditions.push_back(Precondition{PreconditionKind::LINK_NOT_OPERATIONAL,
                                              Subject{SubjectKind::LINK, link.value()}, 0});
    spec.effects.push_back(Effect{EffectKind::SET_LINK_OPERATIONAL,
                                  Subject{SubjectKind::LINK, link.value()}, 1});
    spec.effects.push_back(Effect{EffectKind::SERVICE_REACHABLE_DELTA,
                                  Subject{SubjectKind::SERVICE, service.id.value()}, delta});
    spec.resource_uses.push_back(ResourceUse{spare.id, 1});
    definition.actions.push_back(spec);
  };
  add("restore-l1", 1, 10, 5, 1, l1.id);
  add("replace-l2", 2, 20, 7, 1, l2.id);
  definition.actions[0].id = ActionId::from_value(1);
  definition.actions[1].id = ActionId::from_value(2);

  GoalSpec goal;
  goal.kind = GoalKind::SERVICE_REACHABLE_AT_LEAST;
  goal.subject = Subject{SubjectKind::SERVICE, service.id.value()};
  goal.value = 2;
  goal.weight = 1;
  definition.goals = {goal};

  std::uint64_t fact_id = 1;
  const auto observe = [&evidence, &fact_id](EvidenceKind kind, Subject subject, std::uint64_t value,
                                             AuthorityDomain domain) {
    EvidenceFact fact;
    fact.id = EvidenceId::from_value(fact_id++);
    fact.kind = kind;
    fact.subject = subject;
    fact.value = value;
    fact.generation = Generation{3};
    fact.source_domain = domain;
    fact.source = AuthorityId::from_value(9);
    fact.label = TrustLabel::SYNTHETIC;
    fact.sequence = Sequence{10};
    evidence.facts.push_back(fact);
  };
  observe(EvidenceKind::LINK_OPERATIONAL, Subject{SubjectKind::LINK, l1.id.value()}, 0,
          AuthorityDomain::FABRIC_STATE);
  observe(EvidenceKind::LINK_OPERATIONAL, Subject{SubjectKind::LINK, l2.id.value()}, 0,
          AuthorityDomain::FABRIC_STATE);
  observe(EvidenceKind::NODE_OPERATIONAL, Subject{SubjectKind::NODE, n1.id.value()}, 1,
          AuthorityDomain::FABRIC_STATE);
  observe(EvidenceKind::NODE_OPERATIONAL, Subject{SubjectKind::NODE, n2.id.value()}, 1,
          AuthorityDomain::FABRIC_STATE);
  observe(EvidenceKind::NODE_OPERATIONAL, Subject{SubjectKind::NODE, n3.id.value()}, 1,
          AuthorityDomain::FABRIC_STATE);
  observe(EvidenceKind::SERVICE_REACHABLE_ENDPOINTS,
          Subject{SubjectKind::SERVICE, service.id.value()}, 0, AuthorityDomain::FABRIC_STATE);
  observe(EvidenceKind::RESOURCE_AVAILABLE_UNITS, Subject{SubjectKind::RESOURCE, spare.id.value()},
          2, AuthorityDomain::RESOURCE_LEASE);

  Scenario scenario;
  scenario.request.id = RequestId::from_value(1);
  scenario.request.coordinator_epoch = epoch;
  scenario.request.boot = boot;
  scenario.request.attempt = AttemptId::from_value(1);
  scenario.request.definition = definition;
  scenario.request.evidence = evidence;
  scenario.request.authority = authority_for(epoch, boot, 3);
  scenario.request.policy = scenario_policy(steps);
  scenario.request.definition.canonicalise();
  scenario.request.evidence.canonicalise();
  scenario.note = "SYNTHETIC two-link restoration";
  return scenario;
}

Scenario unreachable() {
  Scenario scenario = teaching(6);
  // A link that is down and that no action in the definition can restore.
  LinkSpec orphan;
  orphan.id = LinkId::from_value(3);
  orphan.endpoint_a = NodeId::from_value(1);
  orphan.endpoint_b = NodeId::from_value(2);
  scenario.request.definition.links.push_back(orphan);
  EvidenceFact fact;
  fact.id = EvidenceId::from_value(100);
  fact.kind = EvidenceKind::LINK_OPERATIONAL;
  fact.subject = Subject{SubjectKind::LINK, orphan.id.value()};
  fact.value = 0;
  fact.generation = Generation{3};
  fact.source_domain = AuthorityDomain::FABRIC_STATE;
  fact.source = AuthorityId::from_value(9);
  fact.label = TrustLabel::SYNTHETIC;
  fact.sequence = Sequence{10};
  scenario.request.evidence.facts.push_back(fact);
  GoalSpec goal;
  goal.kind = GoalKind::LINK_OPERATIONAL;
  goal.subject = Subject{SubjectKind::LINK, orphan.id.value()};
  goal.value = 1;
  goal.weight = 1;
  scenario.request.definition.goals.push_back(goal);
  scenario.request.definition.canonicalise();
  scenario.request.evidence.canonicalise();
  scenario.note = "SYNTHETIC unreachable goal";
  return scenario;
}

Scenario cycle() {
  Scenario scenario = teaching(6);
  scenario.request.definition.actions[0].dependencies.push_back(
      ActionDependency{ActionId::from_value(2), 1});
  scenario.request.definition.actions[1].dependencies.push_back(
      ActionDependency{ActionId::from_value(1), 1});
  scenario.request.definition.canonicalise();
  scenario.note = "SYNTHETIC dependency cycle";
  return scenario;
}

Scenario stale() {
  Scenario scenario = teaching(6);
  for (AuthorityBinding& binding : scenario.request.authority.bindings) {
    binding.required = Generation{4};
    binding.granted = Generation{3};
  }
  scenario.note = "SYNTHETIC stale authority";
  return scenario;
}

Scenario partial() {
  Scenario scenario = teaching(6);
  EvidenceBundle filtered;
  filtered.coordinator_epoch = scenario.request.evidence.coordinator_epoch;
  filtered.boot = scenario.request.evidence.boot;
  for (const EvidenceFact& fact : scenario.request.evidence.facts) {
    if (fact.kind == EvidenceKind::SERVICE_REACHABLE_ENDPOINTS) continue;
    filtered.facts.push_back(fact);
  }
  scenario.request.evidence = filtered;
  scenario.note = "SYNTHETIC missing service evidence";
  return scenario;
}

Scenario budget() {
  Scenario scenario = teaching(6);
  scenario.request.policy.max_nodes_expanded = 1;
  scenario.request.policy.max_generated_states = 1;
  scenario.request.policy.max_frontier_entries = 1;
  scenario.note = "SYNTHETIC exhausted budget";
  return scenario;
}

Scenario random_instance(std::uint64_t seed, std::uint32_t index) {
  // A compact generator that mirrors the fixture used by the differential suite.
  Scenario scenario;
  FabricDefinition definition;
  EvidenceBundle evidence;
  const Epoch epoch = Epoch::from_value(1);
  const BootId boot = BootId::from_value(7);
  evidence.coordinator_epoch = epoch;
  evidence.boot = boot;

  std::uint64_t state = seed * 1000003ull + index;
  const auto next = [&state]() {
    state += 0x9E3779B97F4A7C15ull;
    std::uint64_t value = state;
    value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9ull;
    value = (value ^ (value >> 27)) * 0x94D049BB133111EBull;
    return value ^ (value >> 31);
  };
  const std::uint32_t node_count = 2 + static_cast<std::uint32_t>(next() % 2);
  for (std::uint32_t i = 0; i < node_count; ++i) {
    NodeSpec node;
    node.id = NodeId::from_value(1 + i);
    definition.nodes.push_back(node);
  }
  const std::uint32_t link_count = 1 + static_cast<std::uint32_t>(next() % 3);
  for (std::uint32_t i = 0; i < link_count; ++i) {
    LinkSpec link;
    link.id = LinkId::from_value(1 + i);
    link.endpoint_a = NodeId::from_value(1 + (next() % node_count));
    link.endpoint_b = NodeId::from_value(1 + ((next() % node_count)));
    if (link.endpoint_a == link.endpoint_b) {
      link.endpoint_b = NodeId::from_value(1 + ((link.endpoint_a.value()) % node_count));
    }
    definition.links.push_back(link);
  }
  ServiceSpec service;
  service.id = ServiceId::from_value(1);
  service.max_reachable = 2 + static_cast<std::uint32_t>(next() % 2);
  service.required_reachable = static_cast<std::uint32_t>(next() % (service.max_reachable + 1));
  service.target_reachable =
      service.required_reachable +
      static_cast<std::uint32_t>(next() % (service.max_reachable - service.required_reachable + 1));
  definition.services.push_back(service);

  const std::uint32_t action_count = 2 + static_cast<std::uint32_t>(next() % 3);
  for (std::uint32_t i = 0; i < action_count; ++i) {
    ActionSpec action;
    action.id = ActionId::from_value(1 + i);
    action.name = "a" + std::to_string(i);
    action.blast_radius = static_cast<std::uint32_t>(next() % 4);
    action.disruption = static_cast<std::uint32_t>(next() % 4);
    action.cost_units = next() % 20;
    action.duration_ticks = next() % 8;
    const LinkId link = definition.links[next() % definition.links.size()].id;
    if (next() % 2 == 0) {
      action.effects.push_back(Effect{EffectKind::SET_LINK_OPERATIONAL,
                                      Subject{SubjectKind::LINK, link.value()}, 1});
    } else {
      action.effects.push_back(Effect{EffectKind::SERVICE_REACHABLE_DELTA,
                                      Subject{SubjectKind::SERVICE, service.id.value()}, 1});
    }
    definition.actions.push_back(action);
  }
  GoalSpec goal;
  goal.kind = GoalKind::LINK_OPERATIONAL;
  goal.subject = Subject{SubjectKind::LINK,
                         definition.links[next() % definition.links.size()].id.value()};
  goal.value = 1;
  goal.weight = 1;
  definition.goals.push_back(goal);

  std::uint64_t fact_id = 1;
  for (const LinkSpec& link : definition.links) {
    EvidenceFact fact;
    fact.id = EvidenceId::from_value(fact_id++);
    fact.kind = EvidenceKind::LINK_OPERATIONAL;
    fact.subject = Subject{SubjectKind::LINK, link.id.value()};
    fact.value = next() % 2;
    fact.generation = Generation{3};
    fact.source_domain = AuthorityDomain::FABRIC_STATE;
    fact.source = AuthorityId::from_value(9);
    fact.label = TrustLabel::SYNTHETIC;
    fact.sequence = Sequence{10};
    evidence.facts.push_back(fact);
  }
  for (const NodeSpec& node : definition.nodes) {
    EvidenceFact fact;
    fact.id = EvidenceId::from_value(fact_id++);
    fact.kind = EvidenceKind::NODE_OPERATIONAL;
    fact.subject = Subject{SubjectKind::NODE, node.id.value()};
    fact.value = 1;
    fact.generation = Generation{3};
    fact.source_domain = AuthorityDomain::FABRIC_STATE;
    fact.source = AuthorityId::from_value(9);
    fact.label = TrustLabel::SYNTHETIC;
    fact.sequence = Sequence{10};
    evidence.facts.push_back(fact);
  }
  {
    EvidenceFact fact;
    fact.id = EvidenceId::from_value(fact_id++);
    fact.kind = EvidenceKind::SERVICE_REACHABLE_ENDPOINTS;
    fact.subject = Subject{SubjectKind::SERVICE, service.id.value()};
    fact.value = next() % (service.max_reachable + 1);
    fact.generation = Generation{3};
    fact.source_domain = AuthorityDomain::FABRIC_STATE;
    fact.source = AuthorityId::from_value(9);
    fact.label = TrustLabel::SYNTHETIC;
    fact.sequence = Sequence{10};
    evidence.facts.push_back(fact);
  }

  scenario.request.id = RequestId::from_value(1 + index);
  scenario.request.coordinator_epoch = epoch;
  scenario.request.boot = boot;
  scenario.request.attempt = AttemptId::from_value(1);
  scenario.request.definition = definition;
  scenario.request.evidence = evidence;
  scenario.request.authority = authority_for(epoch, boot, 3);
  scenario.request.policy = scenario_policy(5);
  scenario.request.definition.canonicalise();
  scenario.request.evidence.canonicalise();
  scenario.note = "SYNTHETIC pseudo-random instance";
  return scenario;
}

bool select_scenario(const std::string& name, std::uint64_t steps, Scenario* out, Status* status) {
  if (name.empty() || name == "teaching") {
    *out = teaching(steps);
    return true;
  }
  if (name == "unreachable") {
    *out = unreachable();
    return true;
  }
  if (name == "cycle") {
    *out = cycle();
    return true;
  }
  if (name == "stale") {
    *out = stale();
    return true;
  }
  if (name == "partial") {
    *out = partial();
    return true;
  }
  if (name == "budget") {
    *out = budget();
    return true;
  }
  if (name.rfind("random:", 0) == 0) {
    const std::string rest = name.substr(7);
    const std::size_t colon = rest.find(':');
    if (colon == std::string::npos) {
      *status = Status::error(StatusCode::INVALID_ARGUMENT, "expected random:SEED:CASE");
      return false;
    }
    const std::uint64_t seed = std::strtoull(rest.substr(0, colon).c_str(), nullptr, 10);
    const std::uint32_t index =
        static_cast<std::uint32_t>(std::strtoul(rest.substr(colon + 1).c_str(), nullptr, 10));
    *out = random_instance(seed, index);
    return true;
  }
  *status = Status::error(StatusCode::INVALID_ARGUMENT, "unknown scenario: " + name);
  return false;
}

std::string argument(int argc, char** argv, const char* flag, const char* fallback) {
  for (int index = 1; index + 1 < argc; ++index) {
    if (std::strcmp(argv[index], flag) == 0) return argv[index + 1];
  }
  return fallback;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    std::fputs(kUsage, stdout);
    return 1;
  }
  const std::string command = argv[1];
  if (command == "version") {
    std::printf("nrp-cli %s\n", version_string_with_build().c_str());
    return 0;
  }
  if (command == "scenarios") {
    std::fputs(kUsage, stdout);
    return 0;
  }
  if (command == "plan" || command == "validate" || command == "reference") {
    const std::string scenario_name = argument(argc, argv, "--scenario", "teaching");
    const std::uint64_t steps =
        std::strtoull(argument(argc, argv, "--steps", "6").c_str(), nullptr, 10);
    Scenario scenario;
    Status status = Status::success();
    if (!select_scenario(scenario_name, steps, &scenario, &status)) {
      std::fprintf(stderr, "%s\n", status.to_string().c_str());
      return 1;
    }
    Planner planner;
    const PlanningResult result = planner.plan(scenario.request);
    std::printf("scenario: %s (%s)\n", scenario_name.c_str(), scenario.note);
    std::fputs(result.render().c_str(), stdout);
    if (command == "plan") {
      if (result.plan.has_value()) {
        const ValidationReport report = validate_plan(scenario.request, *result.plan);
        std::printf("validation: %s\n", report.valid ? "VALID" : "INVALID");
        if (!report.valid) std::fputs(report.render().c_str(), stdout);
      }
      return 0;
    }
    if (command == "validate") {
      if (!result.plan.has_value()) {
        std::printf("nothing to validate: the planner did not emit a plan\n");
        return 0;
      }
      const ValidationReport report = validate_plan(scenario.request, *result.plan);
      std::fputs(report.render().c_str(), stdout);
      return report.valid ? 0 : 3;
    }
    ReferenceLimits limits;
    limits.max_plan_steps = steps;
    const ReferenceOutcome reference = reference_solve(scenario.request, limits);
    std::printf("reference: kind=%d plan_found=%d sequences=%llu valid=%llu\n",
                static_cast<int>(reference.kind), reference.plan_found ? 1 : 0,
                static_cast<unsigned long long>(reference.sequences_examined),
                static_cast<unsigned long long>(reference.valid_plans));
    if (reference.plan_found) {
      std::printf("reference objective: %s\n", reference.objective.to_string().c_str());
    }
    return 0;
  }
  if (command == "store") {
    const std::string path = argument(argc, argv, "--path", "");
    const std::uint64_t records =
        std::strtoull(argument(argc, argv, "--records", "4").c_str(), nullptr, 10);
    if (path.empty()) {
      std::fprintf(stderr, "--path is required\n");
      return 1;
    }
    OpenOptions options;
    Result<std::unique_ptr<DurableStore>> store = DurableStore::open(path, options);
    if (!store.ok()) {
      std::fprintf(stderr, "%s\n", store.status().to_string().c_str());
      return 1;
    }
    for (std::uint64_t index = 0; index < records; ++index) {
      CanonicalWriter writer;
      writer.u64(index);
      writer.str("synthetic");
      const Status appended =
          store.value()->append(RecordType::EVIDENCE_LINEAGE, writer.buffer(), nullptr);
      if (!appended.ok()) {
        std::fprintf(stderr, "%s\n", appended.to_string().c_str());
        return 1;
      }
    }
    const Status committed = store.value()->commit_snapshot();
    if (!committed.ok()) {
      std::fprintf(stderr, "%s\n", committed.to_string().c_str());
      return 1;
    }
    std::printf("store %s: epoch=%llu boot=%llu records=%llu last_sequence=%llu fences=%llu\n",
                path.c_str(),
                static_cast<unsigned long long>(store.value()->epoch().value()),
                static_cast<unsigned long long>(store.value()->boot().value()),
                static_cast<unsigned long long>(store.value()->records().size()),
                static_cast<unsigned long long>(store.value()->last_sequence().value),
                static_cast<unsigned long long>(store.value()->fences().size()));
    return 0;
  }
  if (command == "selftest") {
    Scenario scenario = teaching(6);
    Planner planner;
    const PlanningResult result = planner.plan(scenario.request);
    if (result.decision != PlanDecision::PLAN_FOUND || !result.plan.has_value()) {
      std::fprintf(stderr, "selftest: expected a plan, got %s\n", to_string(result.decision));
      return 1;
    }
    const ValidationReport report = validate_plan(scenario.request, *result.plan);
    if (!report.valid) {
      std::fprintf(stderr, "selftest: plan did not validate\n%s", report.render().c_str());
      return 1;
    }
    if (result.plan->steps.size() != 2) {
      std::fprintf(stderr, "selftest: unexpected plan length\n");
      return 1;
    }
    std::printf("selftest OK: %s\n", result.plan->objective.to_string().c_str());
    return 0;
  }
  std::fprintf(stderr, "unknown command: %s\n", command.c_str());
  std::fputs(kUsage, stderr);
  return 1;
}
