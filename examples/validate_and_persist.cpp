// Network Recovery Planner - example: durable lineage across a restart.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include <cstdio>
#include <filesystem>
#include <string>

#include "nrp/persistence.hpp"

using namespace nrp;

int main(int argc, char** argv) {
  const std::string path = argc > 1 ? argv[1] : std::string("nrp_example_store.bin");
  OpenOptions options;

  {
    const Result<std::unique_ptr<DurableStore>> store = DurableStore::open(path, options);
    if (!store.ok()) {
      std::fprintf(stderr, "open failed: %s\n", store.status().to_string().c_str());
      return 1;
    }
    CanonicalWriter writer;
    writer.str("synthetic-definition");
    writer.u32(1);
    (void)store.value()->append(RecordType::DEFINITION, writer.buffer(), nullptr);
    CanonicalWriter policy;
    policy.u32(1);
    (void)store.value()->append(RecordType::POLICY, policy.buffer(), nullptr);
    CanonicalWriter attempt;
    attempt.u64(1);
    // An attempt is dynamic state: it is fenced when the store is reopened.
    (void)store.value()->append(RecordType::ATTEMPT, attempt.buffer(), nullptr);
    const Status committed = store.value()->commit_snapshot();
    if (!committed.ok()) {
      std::fprintf(stderr, "snapshot failed: %s\n", committed.to_string().c_str());
      return 1;
    }
    std::printf("first incarnation: epoch=%llu boot=%llu records=%llu\n",
                static_cast<unsigned long long>(store.value()->epoch().value()),
                static_cast<unsigned long long>(store.value()->boot().value()),
                static_cast<unsigned long long>(store.value()->records().size()));
  }

  {
    const Result<std::unique_ptr<DurableStore>> reopened = DurableStore::open(path, options);
    if (!reopened.ok()) {
      std::fprintf(stderr, "reopen failed: %s\n", reopened.status().to_string().c_str());
      return 1;
    }
    const RecoveryReport& report = reopened.value()->recovery();
    std::printf("reopened: epoch=%llu boot=%llu records=%llu fenced_dynamic=%u torn_tail=%s\n",
                static_cast<unsigned long long>(reopened.value()->epoch().value()),
                static_cast<unsigned long long>(reopened.value()->boot().value()),
                static_cast<unsigned long long>(reopened.value()->records().size()),
                report.fenced_dynamic_records, report.torn_tail_recovered ? "yes" : "no");
    std::printf("fences recorded: %llu\n",
                static_cast<unsigned long long>(reopened.value()->fences().size()));
  }

  std::error_code ec;
  std::filesystem::remove(path, ec);
  std::filesystem::remove(path + ".snapshot", ec);
  return 0;
}
