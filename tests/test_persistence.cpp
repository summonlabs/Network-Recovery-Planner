// Network Recovery Planner - adversarial persistence tests.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "detail/crc32.hpp"
#include "nrp/persistence.hpp"
#include "support/fixture.hpp"
#include "support/test_support.hpp"

using namespace nrp;
using namespace nrp::test;

namespace {

std::string temp_path(const char* name) {
  const std::filesystem::path directory = std::filesystem::temp_directory_path();
  return (directory / (std::string("nrp_test_") + name + ".bin")).string();
}

void remove_store(const std::string& path) {
  std::error_code ec;
  std::filesystem::remove(path, ec);
  std::filesystem::remove(path + ".snapshot", ec);
  std::filesystem::remove(path + ".snapshot.tmp", ec);
}

std::vector<std::uint8_t> read_bytes(const std::string& path) {
  std::ifstream input(path, std::ios::binary);
  return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(input),
                                   std::istreambuf_iterator<char>());
}

void write_bytes(const std::string& path, const std::vector<std::uint8_t>& bytes) {
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  output.write(reinterpret_cast<const char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
}

void write_u16(std::uint8_t* out, std::uint16_t value) {
  out[0] = static_cast<std::uint8_t>(value & 0xFFu);
  out[1] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
}

void write_u32(std::uint8_t* out, std::uint32_t value) {
  for (int index = 0; index < 4; ++index) {
    out[index] = static_cast<std::uint8_t>((value >> (8 * index)) & 0xFFu);
  }
}

void write_u64(std::uint8_t* out, std::uint64_t value) {
  for (int index = 0; index < 8; ++index) {
    out[index] = static_cast<std::uint8_t>((value >> (8 * index)) & 0xFFu);
  }
}

/// Builds a well formed record with arbitrary field values so the store can be
/// attacked with structurally valid but semantically hostile input.
std::vector<std::uint8_t> craft_record(std::uint16_t version, std::uint16_t type,
                                       std::uint64_t sequence, std::uint32_t declared_length,
                                       const std::vector<std::uint8_t>& payload,
                                       bool payload_matches_declared = true) {
  std::vector<std::uint8_t> bytes(kRecordHeaderSize + payload.size(), 0);
  std::uint8_t* header = bytes.data();
  write_u32(header, kRecordMagic);
  write_u16(header + 4, version);
  write_u16(header + 6, type);
  write_u64(header + 12, sequence);
  write_u64(header + 20, 1);
  write_u32(header + 28, declared_length);
  write_u32(header + 32, detail::crc32(payload.data(), payload.size()));
  if (!payload_matches_declared) write_u32(header + 32, 0xDEADBEEFu);
  write_u32(header + 36, detail::crc32(header, 36));
  for (std::size_t index = 0; index < payload.size(); ++index) {
    header[kRecordHeaderSize + index] = payload[index];
  }
  return bytes;
}

std::vector<std::uint8_t> payload_for(std::uint64_t value) {
  CanonicalWriter writer;
  writer.u64(value);
  return writer.take();
}

}  // namespace

NRP_TEST(persistence, append_commit_reopen_advances_incarnation) {
  const std::string path = temp_path("reopen");
  remove_store(path);
  {
    const Result<std::unique_ptr<DurableStore>> store = DurableStore::open(path, OpenOptions{});
    NRP_REQUIRE(store.ok());
    NRP_CHECK(store.value()->recovery().fresh_store);
    NRP_CHECK_EQ(store.value()->epoch().value(), 1ull);
    NRP_CHECK_EQ(store.value()->boot().value(), 1ull);
    for (std::uint64_t index = 0; index < 3; ++index) {
      Sequence sequence{};
      NRP_CHECK(store.value()->append(RecordType::DEFINITION, payload_for(index), &sequence).ok());
      NRP_CHECK_EQ(sequence.value, index + 2);
    }
    NRP_CHECK(store.value()->commit_snapshot().ok());
  }
  {
    const Result<std::unique_ptr<DurableStore>> store = DurableStore::open(path, OpenOptions{});
    NRP_REQUIRE(store.ok());
    NRP_CHECK(!store.value()->recovery().fresh_store);
    NRP_CHECK_EQ(store.value()->epoch().value(), 2ull);
    NRP_CHECK_EQ(store.value()->boot().value(), 2ull);
    NRP_CHECK_EQ(store.value()->recovery().previous_epoch.value(), 1ull);
    // Three definition records plus the boot records of both incarnations.
    NRP_CHECK(store.value()->records().size() >= 3);
    std::size_t definitions = 0;
    for (const DurableRecord& record : store.value()->records()) {
      if (record.type == RecordType::DEFINITION) ++definitions;
    }
    NRP_CHECK_EQ(definitions, static_cast<std::size_t>(3));
  }
  remove_store(path);
}

NRP_TEST(persistence, journal_only_records_survive_without_a_snapshot) {
  const std::string path = temp_path("journal");
  remove_store(path);
  {
    const Result<std::unique_ptr<DurableStore>> store = DurableStore::open(path, OpenOptions{});
    NRP_REQUIRE(store.ok());
    NRP_CHECK(store.value()->append(RecordType::POLICY, payload_for(7), nullptr).ok());
  }
  {
    const Result<std::unique_ptr<DurableStore>> store = DurableStore::open(path, OpenOptions{});
    NRP_REQUIRE(store.ok());
    std::size_t policies = 0;
    for (const DurableRecord& record : store.value()->records()) {
      if (record.type == RecordType::POLICY) ++policies;
    }
    NRP_CHECK_EQ(policies, static_cast<std::size_t>(1));
  }
  remove_store(path);
}

NRP_TEST(persistence, torn_tail_at_every_offset_is_recovered) {
  const std::string path = temp_path("torn");
  remove_store(path);
  std::vector<std::uint8_t> complete;
  {
    const Result<std::unique_ptr<DurableStore>> store = DurableStore::open(path, OpenOptions{});
    NRP_REQUIRE(store.ok());
    for (std::uint64_t index = 0; index < 3; ++index) {
      NRP_CHECK(store.value()->append(RecordType::POLICY, payload_for(index), nullptr).ok());
    }
  }
  complete = read_bytes(path);
  NRP_REQUIRE(complete.size() > 2 * kRecordHeaderSize);
  // The journal begins with the boot record of this incarnation, so record
  // boundaries are derived from the file itself rather than assumed.
  std::vector<std::size_t> boundaries;
  {
    std::size_t offset = 0;
    while (offset + kRecordHeaderSize <= complete.size()) {
      boundaries.push_back(offset);
      const std::uint32_t declared =
          static_cast<std::uint32_t>(complete[offset + 28]) |
          (static_cast<std::uint32_t>(complete[offset + 29]) << 8) |
          (static_cast<std::uint32_t>(complete[offset + 30]) << 16) |
          (static_cast<std::uint32_t>(complete[offset + 31]) << 24);
      offset += kRecordHeaderSize + declared;
    }
    boundaries.push_back(complete.size());
  }
  NRP_REQUIRE(boundaries.size() >= 3);
  const std::size_t second_record_end = boundaries[2];
  const auto is_boundary = [&boundaries](std::size_t length) {
    return std::find(boundaries.begin(), boundaries.end(), length) != boundaries.end();
  };

  for (std::size_t length = second_record_end; length < complete.size(); ++length) {
    std::vector<std::uint8_t> truncated(complete.begin(),
                                        complete.begin() + static_cast<std::ptrdiff_t>(length));
    write_bytes(path, truncated);
    const Result<std::unique_ptr<DurableStore>> store = DurableStore::open(path, OpenOptions{});
    NRP_CHECK_MSG(store.ok(), "torn tail of length " << length << " was refused: "
                                                     << (store.ok() ? std::string()
                                                                    : store.status().to_string()));
    if (!store.ok()) continue;
    if (!is_boundary(length)) {
      // A truncation strictly inside a record is a genuine torn tail and must be
      // reported; a truncation exactly on a boundary is simply a short journal.
      NRP_CHECK_MSG(store.value()->recovery().torn_tail_recovered,
                    "torn tail of length " << length << " was not reported");
    }
    std::size_t policies = 0;
    for (const DurableRecord& record : store.value()->records()) {
      if (record.type == RecordType::POLICY) ++policies;
    }
    NRP_CHECK_MSG(policies <= 3, "length " << length << " produced too many records");
  }
  remove_store(path);
}

NRP_TEST(persistence, corruption_is_refused_not_truncated) {
  const std::string path = temp_path("corrupt");
  remove_store(path);
  {
    const Result<std::unique_ptr<DurableStore>> store = DurableStore::open(path, OpenOptions{});
    NRP_REQUIRE(store.ok());
    NRP_CHECK(store.value()->append(RecordType::POLICY, payload_for(1), nullptr).ok());
    NRP_CHECK(store.value()->append(RecordType::POLICY, payload_for(2), nullptr).ok());
  }
  const std::vector<std::uint8_t> complete = read_bytes(path);
  const std::size_t second_start = kRecordHeaderSize + payload_for(0).size();

  for (std::size_t offset = second_start; offset < complete.size(); ++offset) {
    std::vector<std::uint8_t> corrupted = complete;
    corrupted[offset] ^= 0x5A;
    write_bytes(path, corrupted);
    const Result<std::unique_ptr<DurableStore>> store = DurableStore::open(path, OpenOptions{});
    NRP_CHECK_MSG(!store.ok(), "corruption at offset " << offset << " was accepted");
  }
  // A payload byte of the first record is equally fatal.
  {
    std::vector<std::uint8_t> corrupted = complete;
    corrupted[kRecordHeaderSize] ^= 0x01;
    write_bytes(path, corrupted);
    NRP_CHECK(!DurableStore::open(path, OpenOptions{}).ok());
  }
  // Trailing garbage that is not a record header prefix.
  {
    std::vector<std::uint8_t> garbage = complete;
    garbage.push_back(0xAB);
    garbage.push_back(0xCD);
    write_bytes(path, garbage);
    NRP_CHECK(!DurableStore::open(path, OpenOptions{}).ok());
  }
  // Unsupported format version.
  {
    std::vector<std::uint8_t> unsupported =
        craft_record(static_cast<std::uint16_t>(kPersistenceFormatVersion + 1),
                     static_cast<std::uint16_t>(RecordType::POLICY), 1,
                     static_cast<std::uint32_t>(payload_for(1).size()), payload_for(1));
    write_bytes(path, unsupported);
    const Result<std::unique_ptr<DurableStore>> store = DurableStore::open(path, OpenOptions{});
    NRP_CHECK(!store.ok());
    NRP_CHECK_EQ(static_cast<int>(store.status().code()), static_cast<int>(StatusCode::UNSUPPORTED));
  }
  // Declared payload beyond the configured bound is refused.
  {
    const std::vector<std::uint8_t> oversized =
        craft_record(kPersistenceFormatVersion, static_cast<std::uint16_t>(RecordType::POLICY), 1,
                     8u << 20, payload_for(1));
    write_bytes(path, oversized);
    NRP_CHECK(!DurableStore::open(path, OpenOptions{}).ok());
  }
  // A record whose payload checksum does not match is refused.
  {
    const std::vector<std::uint8_t> bad_crc =
        craft_record(kPersistenceFormatVersion, static_cast<std::uint16_t>(RecordType::POLICY), 1,
                     static_cast<std::uint32_t>(payload_for(1).size()), payload_for(1), false);
    write_bytes(path, bad_crc);
    NRP_CHECK(!DurableStore::open(path, OpenOptions{}).ok());
  }
  // Sequence regression is refused.
  {
    std::vector<std::uint8_t> first = craft_record(
        kPersistenceFormatVersion, static_cast<std::uint16_t>(RecordType::POLICY), 5,
        static_cast<std::uint32_t>(payload_for(1).size()), payload_for(1));
    std::vector<std::uint8_t> second = craft_record(
        kPersistenceFormatVersion, static_cast<std::uint16_t>(RecordType::POLICY), 4,
        static_cast<std::uint32_t>(payload_for(2).size()), payload_for(2));
    first.insert(first.end(), second.begin(), second.end());
    write_bytes(path, first);
    NRP_CHECK(!DurableStore::open(path, OpenOptions{}).ok());
  }
  // An out of domain record type is refused.
  {
    const std::vector<std::uint8_t> bad_type =
        craft_record(kPersistenceFormatVersion, 999,
                     static_cast<std::uint32_t>(1), 8, payload_for(1));
    write_bytes(path, bad_type);
    NRP_CHECK(!DurableStore::open(path, OpenOptions{}).ok());
  }
  remove_store(path);
}

NRP_TEST(persistence, dynamic_state_is_fenced_on_restart) {
  const std::string path = temp_path("fenced");
  remove_store(path);
  {
    const Result<std::unique_ptr<DurableStore>> store = DurableStore::open(path, OpenOptions{});
    NRP_REQUIRE(store.ok());
    NRP_CHECK(store.value()->append(RecordType::ATTEMPT, payload_for(1), nullptr).ok());
    NRP_CHECK(store.value()->append(RecordType::EVIDENCE_LINEAGE, payload_for(2), nullptr).ok());
    NRP_CHECK(store.value()->append(RecordType::DEFINITION, payload_for(3), nullptr).ok());
  }
  {
    const Result<std::unique_ptr<DurableStore>> store = DurableStore::open(path, OpenOptions{});
    NRP_REQUIRE(store.ok());
    NRP_CHECK_EQ(store.value()->recovery().fenced_dynamic_records, 2u);
    NRP_CHECK(store.value()->fences().size() >= 2);
    bool explained = false;
    for (const Explanation& explanation : store.value()->recovery().explanations) {
      if (explanation.code == ReasonCode::PERSISTENCE_STALE_DYNAMIC_STATE_FENCED) explained = true;
    }
    NRP_CHECK(explained);
    bool advanced = false;
    for (const Explanation& explanation : store.value()->recovery().explanations) {
      if (explanation.code == ReasonCode::PERSISTENCE_EPOCH_ADVANCED) advanced = true;
    }
    NRP_CHECK(advanced);
  }
  remove_store(path);
}

NRP_TEST(persistence, bounds_are_enforced) {
  const std::string path = temp_path("bounds");
  remove_store(path);
  OpenOptions options;
  // The bound covers the boot record this incarnation appends on open.
  options.limits.max_records = 3;
  const Result<std::unique_ptr<DurableStore>> store = DurableStore::open(path, options);
  NRP_REQUIRE(store.ok());
  NRP_CHECK(store.value()->append(RecordType::POLICY, payload_for(1), nullptr).ok());
  NRP_CHECK(store.value()->append(RecordType::POLICY, payload_for(2), nullptr).ok());
  const Status third = store.value()->append(RecordType::POLICY, payload_for(3), nullptr);
  NRP_CHECK(!third.ok());
  NRP_CHECK_EQ(static_cast<int>(third.code()), static_cast<int>(StatusCode::EXHAUSTED));
  remove_store(path);
}

NRP_TEST(persistence, snapshot_replacement_leaves_no_temporary) {
  const std::string path = temp_path("snapshot");
  remove_store(path);
  {
    const Result<std::unique_ptr<DurableStore>> store = DurableStore::open(path, OpenOptions{});
    NRP_REQUIRE(store.ok());
    NRP_CHECK(store.value()->append(RecordType::POLICY, payload_for(1), nullptr).ok());
    NRP_CHECK(store.value()->commit_snapshot().ok());
    NRP_CHECK(store.value()->append(RecordType::POLICY, payload_for(2), nullptr).ok());
    NRP_CHECK(store.value()->commit_snapshot().ok());
  }
  NRP_CHECK(std::filesystem::exists(path + ".snapshot"));
  NRP_CHECK(!std::filesystem::exists(path + ".snapshot.tmp"));
  {
    const Result<std::unique_ptr<DurableStore>> store = DurableStore::open(path, OpenOptions{});
    NRP_REQUIRE(store.ok());
    std::size_t policies = 0;
    for (const DurableRecord& record : store.value()->records()) {
      if (record.type == RecordType::POLICY) ++policies;
    }
    NRP_CHECK_EQ(policies, static_cast<std::size_t>(2));
  }
  remove_store(path);
}

NRP_TEST(persistence, plan_records_round_trip_and_reject_tampering) {
  TeachingFabric fabric;
  const PlanRequest request = fabric.request();
  Planner planner;
  const PlanningResult result = planner.plan(request);
  NRP_REQUIRE(result.plan.has_value());
  const std::vector<std::uint8_t> encoded = encode_plan_record(*result.plan);
  const Result<RecoveryPlan> decoded = decode_plan_record(encoded);
  NRP_REQUIRE(decoded.ok());
  NRP_CHECK_EQ(decoded.value().plan_digest, result.plan->plan_digest);
  NRP_CHECK_EQ(decoded.value().steps.size(), result.plan->steps.size());
  for (std::size_t length = 0; length < encoded.size(); ++length) {
    const std::vector<std::uint8_t> truncated(encoded.begin(),
                                              encoded.begin() + static_cast<std::ptrdiff_t>(length));
    NRP_CHECK(!decode_plan_record(truncated).ok());
  }
  std::vector<std::uint8_t> extended = encoded;
  extended.push_back(0);
  NRP_CHECK(!decode_plan_record(extended).ok());
}
