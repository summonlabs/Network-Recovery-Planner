// Network Recovery Planner - versioned, integrity-checked durable store.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#ifndef NRP_PERSISTENCE_HPP
#define NRP_PERSISTENCE_HPP

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "nrp/domain.hpp"
#include "nrp/model.hpp"
#include "nrp/plan.hpp"
#include "nrp/result.hpp"
#include "nrp/version.hpp"

namespace nrp {

/// Durable record types. Only state whose semantics survive a restart is ever
/// persisted: definitions, policy, committed lineage, completed outcomes,
/// fences, attempts and boot/incarnation identity. Live telemetry freshness,
/// leases and in-flight authority are explicitly *not* restorable.
enum class RecordType : std::uint16_t {
  BOOT = 1,
  DEFINITION = 2,
  POLICY = 3,
  COMMITTED_PLAN = 4,
  INFEASIBILITY = 5,
  FENCE = 6,
  ATTEMPT = 7,
  EVIDENCE_LINEAGE = 8,
  COUNT = 9,
};

const char* to_string(RecordType type) noexcept;
bool is_valid(RecordType type) noexcept;
/// True when the record carries dynamic (non-restorable) state that must be
/// fenced when it is recovered after a process restart.
bool is_dynamic_record(RecordType type) noexcept;

inline constexpr std::uint32_t kRecordMagic = 0x4E525044u;  // 'NRPD'
inline constexpr std::size_t kRecordHeaderSize = 40;
inline constexpr std::uint32_t kSnapshotMagic = 0x4E525053u;  // 'NRPS'
inline constexpr std::size_t kSnapshotHeaderSize = 40;

struct DurableRecord {
  RecordType type = RecordType::BOOT;
  Sequence sequence{};
  std::vector<std::uint8_t> payload;
};

struct StoreLimits {
  std::uint32_t max_records = 4096;
  std::uint32_t max_record_bytes = 1u << 20;      // 1 MiB per record
  std::uint64_t max_journal_bytes = 64ull << 20;  // 64 MiB journal
  std::uint32_t max_explanations = 128;
};

struct OpenOptions {
  StoreLimits limits{};
  ModelLimits model_limits{};
  bool create_if_missing = true;
  /// Boot identity to use for this process incarnation. The store advances the
  /// epoch and boot identity on every open; a caller may pass the boot identity
  /// it was started with, which must be strictly greater than the durable one.
  bool advance_epoch = true;
};

struct RecoveryReport {
  bool fresh_store = false;
  Epoch previous_epoch{};
  Epoch current_epoch{};
  BootId previous_boot{};
  BootId current_boot{};
  std::uint64_t records_recovered = 0;
  std::uint64_t torn_tail_bytes = 0;
  bool torn_tail_recovered = false;
  std::uint32_t fenced_dynamic_records = 0;
  std::uint32_t restored_static_records = 0;
  std::vector<Explanation> explanations;
};

/// Append-only journal with transactional snapshot replacement.
///
/// Layout on disk: <path> holds the journal, <path>.snapshot holds the last
/// committed snapshot. Every record is length-delimited, sequence numbered and
/// integrity checked. Opening validates the whole durable state and refuses
/// corrupt, unsupported, regressed or trailing-garbage input.
class DurableStore {
 public:
  static Result<std::unique_ptr<DurableStore>> open(const std::string& path,
                                                    const OpenOptions& options);
  ~DurableStore();
  DurableStore(const DurableStore&) = delete;
  DurableStore& operator=(const DurableStore&) = delete;

  /// Appends a record. When flush_now is true (the default) the record is also
  /// flushed to the operating system before the call returns, which is what makes
  /// a "committed" claim mean "durable". Passing false is only used by fault
  /// injection to model a crash between the write and the flush.
  Status append(RecordType type,
                const std::vector<std::uint8_t>& payload,
                Sequence* out,
                bool flush_now = true);

  /// Commits a snapshot of the current durable state with transactional
  /// replacement (write temp, flush, replace, flush directory).
  Status commit_snapshot();

  /// Writes a fence record for a domain and generation.
  Status record_fence(Fence fence);

  Sequence last_sequence() const noexcept { return last_sequence_; }
  Epoch epoch() const noexcept { return epoch_; }
  BootId boot() const noexcept { return boot_; }
  bool closed() const noexcept { return closed_; }

  const RecoveryReport& recovery() const noexcept { return recovery_; }
  /// Durable records in commit order, bounded by StoreLimits::max_records.
  const std::vector<DurableRecord>& records() const noexcept { return records_; }
  const std::vector<Fence>& fences() const noexcept { return fences_; }

  std::string path() const { return path_; }

 private:
  DurableStore() = default;

  std::string path_;
  std::string snapshot_path_;
  StoreLimits limits_{};
  std::vector<DurableRecord> records_;
  std::vector<Fence> fences_;
  Sequence last_sequence_{};
  Epoch epoch_{};
  BootId boot_{};
  RecoveryReport recovery_{};
  bool closed_ = false;
  void* file_ = nullptr;  // opaque OS handle
};

/// Encodes/decodes a fence payload (canonical, versioned).
void encode_fence(const Fence& fence, CanonicalWriter& writer);
Status decode_fence(CanonicalReader& reader, Fence* out);

/// Encodes/decodes a committed plan record payload.
std::vector<std::uint8_t> encode_plan_record(const RecoveryPlan& plan);
Result<RecoveryPlan> decode_plan_record(const std::vector<std::uint8_t>& payload);

}  // namespace nrp

#endif  // NRP_PERSISTENCE_HPP
