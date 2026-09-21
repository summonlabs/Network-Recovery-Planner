# Network Recovery Planner

Network Recovery Planner 1.0.0 is a C++20 runtime that answers one question for a
disrupted network fabric:

> Given a disrupted fabric, current authoritative evidence, service obligations,
> dependencies, available recovery actions and exact generations, which recovery
> plan should execute, in what order, why is it valid, and when is planning
> proven impossible versus indeterminate?

It computes and validates recovery plans. It **does not** execute repairs, program
routes, drain traffic, isolate nodes or degrade services. Those belong to adjacent
runtimes, and this runtime reaches them only through typed inputs, evidence,
authority references and fences.

Everything in this repository is deterministic. The same request always produces
the same plan, the same proof or the same rejection, down to the digest.

## 1. Exact systems boundary

**Owned here**

* plan search over a declared action set: ordering, preconditions, dependencies,
  exclusion groups, resource constraints, safety floors and goals;
* the lexicographic objective and its exact optimum over the explored space;
* proof of infeasibility with an explicit certificate, or an explicit
  indeterminate outcome when a bound is reached;
* independent re-derivation of every produced plan (`nrp::validate_plan`);
* a slow, independent exact reference solver used as a differential oracle;
* authority binding, generation binding, fencing and revocation rules;
* a versioned, integrity-checked durable store for definitions, policy, committed
  outcomes, fences, attempts and lineage;
* a bounded framed transport, a session authority model and a planning service.

**Not owned here**

* executing a plan (there is no actuator, no route programming, no drain);
* fabric telemetry collection (evidence arrives as typed facts with generations);
* leases, grants or authorization issuance (the planner issues
  `RECOMMENDATION` and records which authority a step *requires*);
* transport security (see section 12);
* any claim about physical switch, NIC, RDMA, InfiniBand or multi-node behaviour.

## 2. Authority and generation model

### 2.1 The five distinct things

The runtime keeps these strictly apart, in types and in code paths:

| Concept | Representation | Never implies |
| --- | --- | --- |
| Observation | `EvidenceFact` with a `Generation`, `Sequence`, `TrustLabel` | authority |
| Eligibility | `AuthorityLevel::ELIGIBILITY` on a binding | authorization |
| Recommendation | `PlanStep::issued_level`, always `RECOMMENDATION` | authorization |
| Authorization | `AuthorityLevel::AUTHORIZATION` required by a step, granted by a binding | application |
| Verified effect | `AuthorityLevel::VERIFIED_EFFECT` (not reachable from the planner) | - |

`PlanStep` records both sides: what the step *requires* from an adjacent runtime
(`required_domain`, `required_level`, `required_generation`) and the strongest
level the planner itself asserts (`issued_level`, fixed at `RECOMMENDATION`).
`validate_plan` fails any plan whose `issued_level` exceeds `RECOMMENDATION`.

### 2.2 Authority domains and binding evaluation

Authority-bearing dependencies are grouped into domains:
`FABRIC_STATE`, `RECOVERY_ADMISSION`, `RESOURCE_LEASE`, `POLICY`,
`EVIDENCE_INGEST`. A request carries an `AuthorityVector` of bindings
`(domain, authority, required generation, granted generation, level)`.

`AuthorityBinding::evaluate()` distinguishes six outcomes and never collapses
them:

| Result | Condition |
| --- | --- |
| `CURRENT` | identity non-zero, `granted == required`, level not `NONE` |
| `STALE` | `granted < required` |
| `INVALID` | `granted > required` (evidence or authority from the future) |
| `UNKNOWN` | no binding for the domain, zero authority identity, or level `NONE` |
| `CONFLICT` | two bindings for the same domain |
| `UNSUPPORTED` | reserved for a declared-unsupported domain |

Absence is `UNKNOWN`, never "current". `AuthorityVector::all_current()` also
fails closed on duplicated domains.

### 2.3 Evidence reconciliation

Every observation carries the generation it was produced at and a per-source
sequence number. Reconciliation (independently implemented twice: once in the
planner, once in the validator) resolves each subject:

* a fact is admissible only when its declared domain matches the subject kind,
  its source domain is established, its `generation` equals the **granted**
  generation, its label is `REAL` or `SYNTHETIC` and its value is inside the
  domain of that subject kind;
* the admissible fact with the highest `sequence` wins; two admissible facts
  with the same sequence and different values are a `CONFLICT`;
* older facts are superseded, not merged;
* anything else leaves the subject `UNKNOWN` with an explicit reason
  (`MISSING`, `STALE`, `AHEAD`, `CONFLICT`, `INVALID`, `UNSUPPORTED`).

`UNKNOWN` propagates as *blocked*, not as satisfied: a precondition on an unknown
subject blocks the step, and a goal on an unknown subject can never be proven
satisfied.

### 2.4 Fences

A `Fence` revokes everything issued under an older epoch/generation. The planner
refuses a request fenced by a later coordinator epoch, or by another boot
incarnation of the same epoch. The planning service additionally refuses any
request whose `coordinator_epoch`/`boot` do not match the running incarnation,
before anything is planned or persisted. Restart writes fence records for every
recovered dynamic record (section 6).

## 3. Product-defining invariants

1. **UNKNOWN is never affirmative.** No unknown subject satisfies a precondition,
   a goal, or an authority check. Fail-closed is the default everywhere.
2. **Matching identity is not matching generation.** A binding is usable only at
   exactly the granted generation.
3. **Observation is not authority; authority is not application.** Levels are
   ordered and enforced; the planner never issues above `RECOMMENDATION`.
4. **Failure to find is never proof of absence.** If the search budget is reached,
   the outcome is `INDETERMINATE_SEARCH_LIMIT`. `PROVEN_INFEASIBLE` is emitted
   only with a certificate.
5. **Every proof states its assumptions.** Certificates carry a non-empty
   assumption list, including policy bounds and whether the step bound was
   binding.
6. **Every plan is independently re-derivable.** `validate_plan` re-implements
   state evolution, evidence reconciliation, resource accounting and objective
   accounting from scratch and compares digests, then objective, then every
   precondition, ordering constraint, authority binding and goal.
7. **Determinism.** `(PLAN_FOUND, objective, canonical action encoding)` is
   invariant under container ordering, insertion order and repeated runs; results
   and digests are computed over canonically ordered structures.
8. **Checked accounting.** Every accumulation is checked for overflow; a 64-bit
   objective overflow is an explicit refusal, not a wrapped value.
9. **Bounded everything.** Definitions, evidence, fences, plans, records,
   sessions, queues, frontiers, histories and explanations all have declared
   bounds; exceeding one produces a deterministic refusal.
10. **Persistence is not liveness.** Durable state survives restart as lineage,
    never as restored freshness or authority.

## 4. Supported problem class

A request is a `PlanRequest`:

* `FabricDefinition` - nodes, links, services (`required` floor, `target`,
  `max_reachable`, `protected`), resources (`CONSUMABLE` cumulative bound,
  `REUSABLE` overlapping-hold bound), actions (preconditions, effects,
  dependencies with occurrence counts, exclusion group memberships, cost, blast
  radius, disruption, duration, resource use, reversibility/compensation,
  required authority domain and level), goals and exclusion groups;
* `EvidenceBundle` - typed facts with generations, sequences, sources and trust
  labels;
* `AuthorityVector`, `PlanPolicy`, `Fence` list, request/attempt identities.

Effects are a closed set: `SET_LINK_OPERATIONAL`, `SET_NODE_OPERATIONAL`,
`SERVICE_REACHABLE_DELTA`, `SET_SERVICE_REACHABLE`, `MARK_RESOURCE_RESTORED`,
`SET_RESOURCE_AVAILABLE`. Preconditions are a closed set: link/node operational
or not, service reachability at least/at most, resource availability at least,
action executed at least. Absolute effects resolve `UNKNOWN` values; deltas on an
unknown value with a non-zero floor are refused.

Outside this class the runtime reports `REJECTED_UNSUPPORTED_PROBLEM` or
`REJECTED_INVALID_REQUEST`; it never guesses.

## 5. Decisions, objective and proofs

### 5.1 Decisions

| Decision | Meaning |
| --- | --- |
| `PLAN_FOUND` | an optimal plan inside the policy bounds, with the objective below |
| `PROVEN_INFEASIBLE` | a certificate proves no plan exists under the stated assumptions |
| `INDETERMINATE_SEARCH_LIMIT` | a search bound was reached; no feasibility claim |
| `INDETERMINATE_INCOMPLETE_EVIDENCE` | the space was exhausted, but a step or goal depends on evidence that does not exist at the granted generation |
| `REJECTED_STALE_AUTHORITY` / `REJECTED_UNKNOWN_AUTHORITY` / `REJECTED_CONFLICTING_AUTHORITY` | the authority vector is not current, absent, or contradictory |
| `REJECTED_FENCED` | a fence or another incarnation revokes the request |
| `REJECTED_INVALID_REQUEST` / `REJECTED_UNSUPPORTED_PROBLEM` | structurally invalid, or well-formed but outside the supported class |
| `REJECTED_EXHAUSTED` | a bounded resource (queue, store, allocation bound) refused the work |

### 5.2 The objective (deterministic, lexicographic)

| # | Component | Enforcement |
| --- | --- | --- |
| 0 | `safety_violations` | hard: a step that deepens a service floor is never admissible |
| 1 | `service_preservation_gap` | hard: same rule, measured as total deepening |
| 2 | `recovery_incompleteness` | soft: service-target shortfall incurred by the plan, with unknown reachability scored at the worst case |
| 3 | `blast_radius` | sum over steps |
| 4 | `action_count` | number of steps |
| 5 | `disruption` | sum over steps |
| 6 | `cost_units` | sum over steps |
| 7 | `duration_ticks` | sum over steps |
| tie-break | canonical action encoding | lexicographic comparison of action identities |

Every step contributes a component-wise non-negative increment, so lexicographic
order is monotone under extension: the first goal-satisfying node expanded by the
uniform-cost search is optimal. That property is what makes the optimality claim
provable rather than empirical.

Goals are hard: a plan that leaves a goal unmet is not a solution at all.

### 5.3 Search and certificates

The search is uniform-cost (Dijkstra) over the finite plan-prefix state space,
ordered by the objective with the encoding as tie-break. A state is dominated by
the best `(objective, encoding)` with which it was reached. The space is finite
because every action is bounded by `max_occurrences`, so:

* frontier empty inside the budget means an **exhaustive proof**
  (`EXHAUSTIVE_SEARCH`);
* a dependency cycle gives a **structural proof** (`DEPENDENCY_CYCLE`, re-derived
  by `validate_certificate`);
* a structural upper bound below a goal value gives a **bound proof**
  (`GOAL_UPPER_BOUND`, re-derived by `validate_certificate`);
* a budget reached first gives `INDETERMINATE_SEARCH_LIMIT`, never a proof.

A `PROVEN_INFEASIBLE` result also requires that every subject referenced by a
precondition or goal is established by evidence; otherwise the answer is
`INDETERMINATE_INCOMPLETE_EVIDENCE`.

## 6. Persistence, restart and lineage

The store is a journal plus a snapshot, both versioned and integrity-checked.

* **Record framing (40 bytes)**: magic `NRPD`, format version, type, flags,
  reserved, sequence, epoch, payload length, payload CRC-32, header CRC-32. The
  declared payload length is checked against the configured bound before any
  allocation.
* **Integrity**: both header and payload are CRC-32 checked before a single
  payload byte is interpreted. A payload CRC failure is corruption and is
  refused; it is never truncated away.
* **Torn tails only**: the store recovers only a *strict prefix* of a trailing
  record (fewer bytes than the record declares, with the bytes present matching
  the header prefix). The recovery is reported
  (`PERSISTENCE_TORN_TAIL_RECOVERED`) and the journal is truncated to the last
  complete boundary. Trailing garbage that is not a header prefix is refused.
* **Refusals**: bad magic, unsupported version, out-of-domain record type,
  oversized declared payload, sequence regression, non-increasing sequences,
  trailing garbage, malformed payloads and torn *snapshots* are all refused with
  a specific status.
* **Snapshots**: written to a temporary file, flushed, then installed by
  transactional replacement; only afterwards is the journal reset. Windows uses
  `MoveFileEx(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)`.
* **Ordering**: `append()` writes and flushes (stdio flush plus commit-to-disk)
  before it returns, so "committed" always means "durable".
* **Restart**: opening a store advances the coordinator epoch and the boot
  incarnation, appends a `BOOT` record, and writes one `FENCE` record for every
  recovered dynamic record (`ATTEMPT`, `EVIDENCE_LINEAGE`). Recovered dynamic
  state is reported as fenced and is never restored as live.

Persisted: definitions, policy, committed plans, infeasibility outcomes, fences,
attempts and evidence lineage. Not restored: telemetry freshness, leases,
in-flight authority, acknowledged-but-uncommitted work.

## 7. Wire protocol

Fixed 56-byte header, little endian, protocol version 1:

```text
 0 magic 'NRPF' u32      4 version u16        6 type u16
 8 flags u16            10 reserved u16      12 session_id u64
20 epoch u64            28 boot u64          36 sequence u64
44 payload_length u32   48 payload_crc32 u32 52 header_crc32 u32 (over bytes 0..51)
```

Frames: `HELLO`, `HELLO_ACK`, `PLAN_REQUEST`, `PLAN_RESPONSE`,
`VALIDATE_REQUEST`, `VALIDATE_RESPONSE`, `STATUS_REQUEST`,
`STATUS_RESPONSE`, `BYE`, `ERROR_FRAME` (the type is named `ERROR_FRAME`
because `ERROR` is a platform macro in `wingdi.h`; a public header may not
collide with it).

Rules enforced by the server: the first frame must be `HELLO`; every later frame
must carry the exact `(session_id, epoch, boot)` triple established at handshake
time and a strictly increasing client sequence; declared payloads above the bound
are refused before allocation; flags and reserved bits must be zero; a decode
failure is sticky (an error frame is sent and the connection is closed, never
resynchronised). Each connection is served by its own thread; a truncated frame
stalls only that connection, and shutdown releases it.

Two live sessions can never act under one another's identity: the session
registry validates the authority triple on every frame, and the planning service
additionally refuses any request whose payload is scoped to another coordinator
epoch or boot incarnation (`REJECTED_FENCED`).

## 8. Build, install and use

Requirements: CMake 3.20 or newer, a C++20 compiler, Ninja or another generator.

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DNRP_WERROR=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure

cmake --install build --prefix /path/to/prefix
```

Options: `NRP_BUILD_TESTS`, `NRP_BUILD_TOOLS`, `NRP_BUILD_EXAMPLES`,
`NRP_STRICT` (strict warning set, default on), `NRP_WERROR`, `NRP_ASAN`.

Downstream use is a normal CMake package:

```cmake
find_package(NetworkRecoveryPlanner CONFIG REQUIRED)
target_link_libraries(your_target PRIVATE nrp::network_recovery_planner)
```

`examples/downstream/` is a complete independent project that does exactly
this; see section 11 for the verified run.

## 9. Tools and examples

```sh
nrp-cli version
nrp-cli selftest
nrp-cli scenarios
nrp-cli plan      --scenario teaching      # or unreachable|cycle|stale|partial|budget|random:S:N
nrp-cli validate  --scenario teaching
nrp-cli reference --scenario teaching      # slow exact solver, for cross-checking
nrp-cli store     --path store.bin --records 4

nrp-server --port 0 --store store.bin --port-file port.txt --workers 4 --run-forever
nrp_example_plan
nrp_example_validate store.bin
```

The server prints `NRP_SERVER_READY port=<p> epoch=<e> boot=<b>` and, when asked,
writes the same triple to a port file. `--crash-point` selects a documented fault
injection boundary (section 10.4).

## 10. Evidence: what was actually exercised

### 10.1 REAL on this host

| Evidence | Detail |
| --- | --- |
| Toolchain | MSVC 14.44.35207 (Visual Studio 2022 BuildTools), Windows SDK 10.0.26100, CMake 4.3.2, Ninja 1.13.2, Windows 11 Pro, 16 logical cores |
| Release build | `/W4 /permissive- /WX`, 11/11 suites pass |
| Debug build | `/W4 /permissive- /WX`, 11/11 suites pass |
| AddressSanitizer | MSVC `/fsanitize=address`, Debug, all 11 suites pass (166 s); no findings |
| Static analysis | MSVC `/analyze` over the library: no errors; only system-header advisories and a resolved C6262 (16 KiB stack buffer moved to the heap) |
| Real processes | the multiprocess suite spawns real `nrp-server` processes and hard-kills them (`TerminateProcess`, exit code 70) at durable boundaries |
| Real sockets | loopback TCP against the framed protocol, including hostile frames |
| Install + consumer | `cmake --install` into a prefix, then an independent project outside the source tree built with `find_package(... CONFIG REQUIRED)`, linked and run (section 11) |

### 10.2 SYNTHETIC

All fabric fixtures. `TeachingFabric`, the seeded instance generator and the
`nrp-cli` scenarios are deterministic synthetic models labelled `SYNTHETIC` in
evidence facts and in tool output. No physical switch, NIC, RDMA, InfiniBand or
multi-node hardware was involved anywhere in this work.

### 10.3 UNSUPPORTED on this host

| Claim | Status |
| --- | --- |
| Physical switch/NIC/RDMA/InfiniBand behaviour | **UNSUPPORTED**: no such hardware was exercised; no metadata or stub stands in for it |
| Secure/authenticated transport | **UNSUPPORTED**: the framed protocol assumes a trusted channel (section 12) |
| Cross-machine distributed coordination | **UNSUPPORTED**: multiprocess proof is loopback-only on one host |
| GCC/Clang sanitizer builds | **UNSUPPORTED**: no GCC or Clang toolchain is installed on this host |

### 10.4 Fault injection boundaries

`AFTER_ATTEMPT_APPEND_BEFORE_FLUSH` (bytes written, not flushed),
`AFTER_COMMIT_BEFORE_PUBLISH` (durable outcome, acknowledgement lost) and
`AFTER_PUBLISH_BEFORE_ACK` (response handed to the transport, then death). Each is
exercised by the multiprocess suite, which asserts the resulting state is
conservative: the client observes a failure rather than a fabricated success, the
durable store still holds the committed outcome, reopening advances the
incarnation, and pre-restart dynamic records are fenced.

## 11. Verification results

| Suite | Tests | Checks | Result |
| --- | --- | --- | --- |
| `nrp_test_core` | 8 | 1549 | pass |
| `nrp_test_model` | 5 | 38 | pass |
| `nrp_test_planner` | 16 | 118 | pass |
| `nrp_test_validate` | 14 | 32 | pass |
| `nrp_test_adversarial` | 12 | 42 | pass |
| `nrp_test_persistence` | 8 | 1034 | pass |
| `nrp_test_protocol` | 7 | 4624 | pass |
| `nrp_test_concurrency` | 8 | 63 | pass |
| `nrp_test_scale` | 3 | 20 | pass |
| `nrp_test_differential` | 3 | 8766 | pass |
| `nrp_test_multiprocess` | 6 | 79 | pass |
| **total** | **90** | **16 345** | **11/11 suites pass** |

Differential coverage: **3250 seeded instances** (3000 at depth at most 5, 250 at
depth at most 6) where the production planner and the independent exact reference
solver agree on the decision, the objective vector *and* the canonical encoding;
1766 plans found, 1234 proven infeasible, 0 indeterminate, 0 disagreements.

Scale (completed work, not submission latency), corridor instances where every
link must be restored:

| Links | Steps | Nodes expanded | States generated | Frontier high water | Dominated revisits | Wall time |
| --- | --- | --- | --- | --- | --- | --- |
| 4 | 4 | 15 | 32 | 7 | 17 | 0.17 ms |
| 6 | 6 | 63 | 192 | 24 | 129 | 0.38 ms |
| 8 | 8 | 255 | 1024 | 85 | 769 | 2.72 ms |
| 10 | 10 | 1023 | 5120 | 307 | 4097 | 9.38 ms |

Retained state stays bounded by policy; when the budget is reached at this scale
the result is `INDETERMINATE_SEARCH_LIMIT`, never a weaker feasibility claim.

Install and consumer:

```text
cmake --install build --prefix <prefix>            # headers, library, tools, package config
<outside the source tree>:
  cmake -S . -B build -DCMAKE_PREFIX_PATH=<prefix>
  cmake --build build && ./build/nrp_consumer
  -> linked against Network Recovery Planner 1.0.0 (domain format 1, persistence format 1, protocol 1)
  -> plan objective [0 0 0 0 1 0 0 0] steps=1 validated=yes
```

## 12. Trust boundary and deliberate non-goals

* The framed transport provides **integrity and structure, not security**: CRC-32
  detects corruption, not tampering, and there is no authentication,
  authorization or encryption on the wire. Deploy it on a trusted channel or
  terminate TLS in front of it. The session authority model described in section 7
  is an *identity consistency* mechanism, not a security mechanism.
* Identity digests are non-cryptographic (two mixed 64-bit accumulators). They
  detect corruption and give deterministic identity; they are not a MAC and must
  not be used as one.
* Recovery is modelled, not executed: a plan is a recommendation plus the exact
  authority it would need.
* Only the declared effect set is modelled. If an action can change something the
  definition does not declare, the definition is wrong and the runtime cannot
  detect that for you.

## 13. Genuine limitations

1. **Evidence must be complete for what a plan depends on.** Subjects with no
   admissible evidence are `UNKNOWN`; steps and goals that depend on them are
   never satisfied. This is deliberate, and it means a sparse evidence feed
   produces `INDETERMINATE_INCOMPLETE_EVIDENCE` rather than a guess.
2. **No cross-action concurrency.** A plan is a sequence. Reusable-resource
   overlap is modelled with hold windows in *steps*, not wall-clock parallelism.
   Modelling simultaneous independent repairs would require a different state
   space and is out of scope for 1.0.0.
3. **Iteration is bounded and explicit.** Repeated execution is expressed with
   `max_occurrences` and occurrence-count dependencies; there is no unbounded
   retry loop, because that would make the state space infinite and destroy the
   exhaustiveness proof.
4. **Search is exact but worst-case exponential.** The budget bounds it, and the
   bound is reported, not hidden. Large action sets return
   `INDETERMINATE_SEARCH_LIMIT` rather than a heuristic plan.
5. **`PROVEN_INFEASIBLE` is relative to the request policy.** The certificate
   lists the assumptions, including the plan-length bound when it is binding
   (`policy.max_plan_steps` smaller than the total occurrence bound) and whether
   irreversible actions were excluded.
6. **The reference solver refuses instances deeper than 12 steps** and reports
   `LIMIT_REACHED`; it is an oracle for small instances, not a second production
   path.
7. **Explanations are bounded.** The explanation log has a capacity; when it is
   reached, the truncation is recorded rather than silently dropped.
8. **The store keeps all recovered records in memory**, bounded by
   `StoreLimits::max_records` (4096 by default). There is no streaming replay of
   a huge journal.
9. **Wall-clock time is not part of any decision.** Durations are declared
   integers in ticks. There is no clock, no timeout and no wall-time-dependent
   behaviour anywhere in the runtime.

## 14. Repository layout

```text
include/nrp/        public headers (planner, validator, model, persistence, protocol, runtime)
src/                implementation; validate.cpp and reference_solver.cpp are deliberately independent
tools/              nrp-cli, nrp-server
examples/           plan_recovery, validate_and_persist, downstream consumer project
tests/              eleven suites plus the deterministic fixture and process helpers
docs/               concurrency and ownership audit
```

## License
Apache License 2.0. Copyright 2026 Summon Software Labs.
