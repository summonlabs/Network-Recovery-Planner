// Network Recovery Planner - versioned, integrity-checked durable store.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// Durability contract
// -------------------
//   * every record is length delimited, sequence numbered and integrity checked
//     twice (header CRC and payload CRC) before a single payload byte is used;
//   * records are flushed to the operating system from append(), so a claim of
//     "committed" always means "flushed", never "buffered";
//   * snapshots are installed by transactional replacement (write temporary,
//     flush, replace, flush);
//   * corrupt, unsupported, regressed or trailing-garbage journals are refused,
//     never silently truncated;
//   * only a genuine torn tail (a strict prefix of a record that the file ends
//     inside of) is recovered, and the recovery is reported;
//   * opening the store advances the coordinator epoch and the boot identity and
//     fences every recovered dynamic record. Nothing dynamic is restored as
//     live: persistence is not liveness.
#include "nrp/persistence.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>

#ifdef _WIN32
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

#include "detail/crc32.hpp"
#include "nrp/codec.hpp"

namespace nrp {
namespace {

std::uint32_t read_u32(const std::uint8_t* data) {
  return static_cast<std::uint32_t>(data[0]) | (static_cast<std::uint32_t>(data[1]) << 8) |
         (static_cast<std::uint32_t>(data[2]) << 16) | (static_cast<std::uint32_t>(data[3]) << 24);
}

std::uint64_t read_u64(const std::uint8_t* data) {
  std::uint64_t value = 0;
  for (int index = 0; index < 8; ++index) {
    value |= static_cast<std::uint64_t>(data[index]) << (8 * index);
  }
  return value;
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

/// Result of scanning a byte range of framed records.
struct ScanResult {
  Status status = Status::success();
  std::vector<DurableRecord> records;
  std::uint64_t good_bytes = 0;
  std::uint64_t torn_tail_bytes = 0;
  bool torn_tail = false;
};

ScanResult scan_records(const std::vector<std::uint8_t>& bytes,
                        const StoreLimits& limits,
                        std::uint64_t minimum_sequence) {
  ScanResult result;
  std::size_t offset = 0;
  std::uint64_t last_seen = 0;
  while (offset < bytes.size()) {
    const std::size_t remaining = bytes.size() - offset;
    if (remaining < kRecordHeaderSize) {
      // A strict prefix of a header: a torn write, recoverable.
      const std::uint8_t* tail = bytes.data() + offset;
      const std::size_t magic_bytes = remaining < 4 ? remaining : 4;
      bool prefix_of_magic = true;
      const std::uint8_t magic[4] = {static_cast<std::uint8_t>(kRecordMagic & 0xFFu),
                                     static_cast<std::uint8_t>((kRecordMagic >> 8) & 0xFFu),
                                     static_cast<std::uint8_t>((kRecordMagic >> 16) & 0xFFu),
                                     static_cast<std::uint8_t>((kRecordMagic >> 24) & 0xFFu)};
      for (std::size_t index = 0; index < magic_bytes; ++index) {
        if (tail[index] != magic[index]) prefix_of_magic = false;
      }
      if (!prefix_of_magic) {
        result.status = Status::error(StatusCode::CORRUPT,
                                      "trailing bytes are not a record header prefix");
        return result;
      }
      result.torn_tail = true;
      result.torn_tail_bytes = remaining;
      result.good_bytes = offset;
      return result;
    }
    const std::uint8_t* header = bytes.data() + offset;
    const std::uint32_t magic = read_u32(header);
    if (magic != kRecordMagic) {
      result.status = Status::error(StatusCode::CORRUPT, "record magic mismatch");
      return result;
    }
    const std::uint16_t version = static_cast<std::uint16_t>(header[4] | (header[5] << 8));
    if (version != kPersistenceFormatVersion) {
      result.status = Status::error(StatusCode::UNSUPPORTED,
                                    "record format version is not supported: " +
                                        std::to_string(version));
      return result;
    }
    const std::uint16_t raw_type = static_cast<std::uint16_t>(header[6] | (header[7] << 8));
    if (raw_type == 0 || raw_type >= static_cast<std::uint16_t>(RecordType::COUNT)) {
      result.status = Status::error(StatusCode::CORRUPT, "record type is outside the domain");
      return result;
    }
    const std::uint32_t header_crc = read_u32(header + 36);
    const std::uint32_t computed_header_crc = detail::crc32(header, 36);
    if (header_crc != computed_header_crc) {
      result.status = Status::error(StatusCode::CORRUPT, "record header checksum mismatch");
      return result;
    }
    const std::uint64_t sequence = read_u64(header + 12);
    const std::uint32_t payload_length = read_u32(header + 28);
    const std::uint32_t payload_crc = read_u32(header + 32);
    if (payload_length > limits.max_record_bytes) {
      result.status = Status::error(StatusCode::CORRUPT,
                                    "record declares a payload beyond the configured bound");
      return result;
    }
    const std::size_t total = kRecordHeaderSize + payload_length;
    if (remaining < total) {
      // The record declares more bytes than the file holds: a genuine torn tail.
      result.torn_tail = true;
      result.torn_tail_bytes = remaining;
      result.good_bytes = offset;
      return result;
    }
    const std::uint8_t* payload = header + kRecordHeaderSize;
    if (detail::crc32(payload, payload_length) != payload_crc) {
      result.status = Status::error(
          StatusCode::CORRUPT,
          "record payload checksum mismatch at sequence " + std::to_string(sequence));
      return result;
    }
    if (last_seen != 0 && sequence <= last_seen) {
      result.status = Status::error(StatusCode::CORRUPT,
                                    "record sequences are not strictly increasing at " +
                                        std::to_string(sequence));
      return result;
    }
    last_seen = sequence;
    if (sequence > minimum_sequence) {
      DurableRecord record;
      record.type = static_cast<RecordType>(raw_type);
      record.sequence = Sequence{sequence};
      record.payload.assign(payload, payload + payload_length);
      result.records.push_back(std::move(record));
    }
    offset += total;
  }
  result.good_bytes = offset;
  return result;
}

Status flush_file(std::FILE* file) {
  if (std::fflush(file) != 0) {
    return Status::error(StatusCode::IO_ERROR, "fflush failed");
  }
#ifdef _WIN32
  if (_commit(_fileno(file)) != 0) {
    return Status::error(StatusCode::IO_ERROR, "commit to disk failed");
  }
#else
  if (fsync(fileno(file)) != 0) {
    return Status::error(StatusCode::IO_ERROR, "fsync failed");
  }
#endif
  return Status::success();
}

Status read_file(const std::string& path, std::uint64_t max_bytes, std::vector<std::uint8_t>* out) {
  std::error_code ec;
  const std::uintmax_t size = std::filesystem::file_size(path, ec);
  if (ec) return Status::error(StatusCode::IO_ERROR, "cannot stat " + path + ": " + ec.message());
  if (size > max_bytes) {
    return Status::error(StatusCode::CORRUPT, "durable state exceeds the configured bound");
  }
  std::FILE* file = std::fopen(path.c_str(), "rb");
  if (file == nullptr) return Status::error(StatusCode::IO_ERROR, "cannot open " + path);
  out->assign(static_cast<std::size_t>(size), 0);
  const std::size_t read = out->empty() ? 0 : std::fread(out->data(), 1, out->size(), file);
  const bool short_read = read != out->size();
  std::fclose(file);
  if (short_read) return Status::error(StatusCode::IO_ERROR, "short read from " + path);
  return Status::success();
}

std::vector<std::uint8_t> frame_record(RecordType type,
                                       Sequence sequence,
                                       Epoch epoch,
                                       const std::vector<std::uint8_t>& payload) {
  std::vector<std::uint8_t> bytes(kRecordHeaderSize + payload.size(), 0);
  std::uint8_t* header = bytes.data();
  write_u32(header, kRecordMagic);
  write_u16(header + 4, static_cast<std::uint16_t>(kPersistenceFormatVersion));
  write_u16(header + 6, static_cast<std::uint16_t>(type));
  write_u16(header + 8, 0);
  write_u16(header + 10, 0);
  write_u64(header + 12, sequence.value);
  write_u64(header + 20, epoch.value());
  write_u32(header + 28, static_cast<std::uint32_t>(payload.size()));
  write_u32(header + 32, detail::crc32(payload.data(), payload.size()));
  write_u32(header + 36, detail::crc32(header, 36));
  if (!payload.empty()) {
    std::memcpy(header + kRecordHeaderSize, payload.data(), payload.size());
  }
  return bytes;
}

std::vector<std::uint8_t> encode_epoch_payload(Epoch previous_epoch,
                                               BootId previous_boot,
                                               Epoch current_epoch,
                                               BootId current_boot) {
  CanonicalWriter writer;
  writer.u32(kPersistenceFormatVersion);
  writer.u64(previous_epoch.value());
  writer.u64(previous_boot.value());
  writer.u64(current_epoch.value());
  writer.u64(current_boot.value());
  return writer.take();
}

}  // namespace

const char* to_string(RecordType type) noexcept {
  switch (type) {
    case RecordType::BOOT: return "BOOT";
    case RecordType::DEFINITION: return "DEFINITION";
    case RecordType::POLICY: return "POLICY";
    case RecordType::COMMITTED_PLAN: return "COMMITTED_PLAN";
    case RecordType::INFEASIBILITY: return "INFEASIBILITY";
    case RecordType::FENCE: return "FENCE";
    case RecordType::ATTEMPT: return "ATTEMPT";
    case RecordType::EVIDENCE_LINEAGE: return "EVIDENCE_LINEAGE";
    case RecordType::COUNT: return "COUNT";
  }
  return "UNRECOGNISED_RECORD_TYPE";
}

bool is_valid(RecordType type) noexcept {
  return type != RecordType::COUNT;
}

bool is_dynamic_record(RecordType type) noexcept {
  // Attempts and observations carry liveness that a restart destroys. Plans and
  // proofs are completed outcomes and stay valid as lineage.
  return type == RecordType::ATTEMPT || type == RecordType::EVIDENCE_LINEAGE;
}

std::vector<std::uint8_t> encode_plan_record(const RecoveryPlan& plan) {
  CanonicalWriter writer;
  encode_plan(plan, writer);
  writer.u64(plan.plan_digest.hi);
  writer.u64(plan.plan_digest.lo);
  return writer.take();
}

Result<RecoveryPlan> decode_plan_record(const std::vector<std::uint8_t>& payload) {
  CanonicalReader reader(payload);
  RecoveryPlan plan;
  Status status = decode_plan(reader, default_model_limits(), &plan);
  if (!status.ok()) return status;
  plan.plan_digest.hi = reader.u64();
  plan.plan_digest.lo = reader.u64();
  if (!reader.ok()) return reader.status();
  status = reader.require_end();
  if (!status.ok()) return status;
  return plan;
}

DurableStore::~DurableStore() {
  if (file_ != nullptr) {
    std::fclose(static_cast<std::FILE*>(file_));
    file_ = nullptr;
  }
}

Result<std::unique_ptr<DurableStore>> DurableStore::open(const std::string& path,
                                                         const OpenOptions& options) {
  if (path.empty() || path.find('\0') != std::string::npos) {
    return Status::error(StatusCode::INVALID_ARGUMENT, "store path must be a non-empty path");
  }
  std::error_code ec;
  const std::filesystem::path target(path);
  if (std::filesystem::is_directory(target, ec)) {
    return Status::error(StatusCode::INVALID_ARGUMENT, "store path is a directory");
  }
  const std::filesystem::path parent = target.parent_path();
  if (!parent.empty() && !std::filesystem::is_directory(parent, ec)) {
    return Status::error(StatusCode::IO_ERROR, "store directory does not exist");
  }

  std::unique_ptr<DurableStore> store(new DurableStore());
  store->path_ = path;
  store->snapshot_path_ = path + ".snapshot";
  store->limits_ = options.limits;

  RecoveryReport& report = store->recovery_;
  const bool journal_exists = std::filesystem::exists(target, ec);
  const bool snapshot_exists = std::filesystem::exists(store->snapshot_path_, ec);
  report.fresh_store = !journal_exists && !snapshot_exists;

  Sequence snapshot_sequence{};
  if (snapshot_exists) {
    std::vector<std::uint8_t> bytes;
    Status status = read_file(store->snapshot_path_, options.limits.max_journal_bytes, &bytes);
    if (!status.ok()) return status;
    if (bytes.size() < kSnapshotHeaderSize) {
      return Status::error(StatusCode::CORRUPT, "snapshot header is truncated");
    }
    if (read_u32(bytes.data()) != kSnapshotMagic) {
      return Status::error(StatusCode::CORRUPT, "snapshot magic mismatch");
    }
    const std::uint16_t version = static_cast<std::uint16_t>(bytes[4] | (bytes[5] << 8));
    if (version != kPersistenceFormatVersion) {
      return Status::error(StatusCode::UNSUPPORTED, "snapshot format version is not supported");
    }
    if (read_u32(bytes.data() + 36) != detail::crc32(bytes.data(), 36)) {
      return Status::error(StatusCode::CORRUPT, "snapshot header checksum mismatch");
    }
    const std::uint32_t payload_length = read_u32(bytes.data() + 12);
    const std::uint32_t payload_crc = read_u32(bytes.data() + 16);
    if (bytes.size() != kSnapshotHeaderSize + payload_length) {
      return Status::error(StatusCode::CORRUPT, "snapshot length does not match its header");
    }
    if (detail::crc32(bytes.data() + kSnapshotHeaderSize, payload_length) != payload_crc) {
      return Status::error(StatusCode::CORRUPT, "snapshot payload checksum mismatch");
    }
    snapshot_sequence = Sequence{read_u64(bytes.data() + 20)};
    report.previous_epoch = Epoch::from_value(read_u64(bytes.data() + 28));
    std::vector<std::uint8_t> payload(bytes.begin() + kSnapshotHeaderSize, bytes.end());
    ScanResult scan = scan_records(payload, options.limits, 0);
    if (!scan.status.ok()) return scan.status;
    if (scan.torn_tail) {
      // A snapshot is installed by transactional replacement, so a torn
      // snapshot cannot be a legitimate crash artifact: refuse it.
      return Status::error(StatusCode::CORRUPT, "snapshot contains a torn record");
    }
    store->records_ = std::move(scan.records);
    report.restored_static_records = static_cast<std::uint32_t>(store->records_.size());
  }

  if (journal_exists) {
    std::vector<std::uint8_t> bytes;
    Status status = read_file(path, options.limits.max_journal_bytes, &bytes);
    if (!status.ok()) return status;
    ScanResult scan = scan_records(bytes, options.limits, snapshot_sequence.value);
    if (!scan.status.ok()) return scan.status;
    for (DurableRecord& record : scan.records) {
      store->records_.push_back(std::move(record));
    }
    if (scan.torn_tail) {
      report.torn_tail_recovered = true;
      report.torn_tail_bytes = scan.torn_tail_bytes;
      Explanation explanation;
      explanation.code = ReasonCode::PERSISTENCE_TORN_TAIL_RECOVERED;
      explanation.detail_a = scan.torn_tail_bytes;
      explanation.text = "a strictly partial trailing record was discarded";
      report.explanations.push_back(explanation);
      // Truncate the journal to the last complete record boundary.
      std::FILE* truncate = std::fopen(path.c_str(), "rb+");
      if (truncate == nullptr) {
        return Status::error(StatusCode::IO_ERROR, "cannot open the journal to recover a torn tail");
      }
#ifdef _WIN32
      const int seek_result = _chsize_s(_fileno(truncate), static_cast<__int64>(scan.good_bytes));
#else
      const int seek_result = ftruncate(fileno(truncate), static_cast<off_t>(scan.good_bytes));
#endif
      std::fclose(truncate);
      if (seek_result != 0) {
        return Status::error(StatusCode::IO_ERROR, "cannot truncate the recovered journal tail");
      }
    }
  }

  // Bounded retained history: the store refuses to grow without limit rather
  // than degrading silently.
  if (store->records_.size() > options.limits.max_records) {
    return Status::error(StatusCode::EXHAUSTED, "durable record count exceeds the configured bound");
  }

  Sequence last{};
  Epoch durable_epoch{};
  BootId durable_boot{};
  for (const DurableRecord& record : store->records_) {
    if (record.sequence.value <= last.value && last.value != 0) {
      return Status::error(StatusCode::CORRUPT, "durable sequences are not strictly increasing");
    }
    last = record.sequence;
    if (record.type == RecordType::BOOT) {
      CanonicalReader reader(record.payload);
      (void)reader.u32();
      (void)reader.u64();
      (void)reader.u64();
      durable_epoch = Epoch::from_value(reader.u64());
      durable_boot = BootId::from_value(reader.u64());
      if (!reader.ok()) {
        return Status::error(StatusCode::CORRUPT, "boot record payload is malformed");
      }
    }
    if (record.type == RecordType::FENCE) {
      CanonicalReader reader(record.payload);
      Fence fence;
      const Status fence_status = decode_fence(reader, &fence);
      if (!fence_status.ok()) return fence_status;
      store->fences_.push_back(std::move(fence));
    }
  }
  store->last_sequence_ = last;
  report.previous_epoch = durable_epoch;
  report.previous_boot = durable_boot;
  report.records_recovered = store->records_.size();

  store->epoch_ = options.advance_epoch ? Epoch::from_value(durable_epoch.value() + 1)
                                        : durable_epoch;
  store->boot_ = BootId::from_value(options.advance_epoch ? durable_boot.value() + 1
                                                          : durable_boot.value());

  std::FILE* file = std::fopen(path.c_str(), "ab");
  if (file == nullptr) {
    if (!options.create_if_missing) {
      return Status::error(StatusCode::IO_ERROR, "cannot open the journal for append");
    }
    file = std::fopen(path.c_str(), "wb");
    if (file == nullptr) {
      return Status::error(StatusCode::IO_ERROR, "cannot create the journal");
    }
  }
  store->file_ = file;

  // Fence every recovered dynamic record and publish the new incarnation.
  std::uint32_t fenced = 0;
  // The fencing pass appends fence records, so it must not iterate the record
  // vector it is appending to: the candidates are copied out first.
  std::vector<Sequence> dynamic_sequences;
  for (const DurableRecord& record : store->records_) {
    if (is_dynamic_record(record.type)) dynamic_sequences.push_back(record.sequence);
  }
  for (const Sequence& recovered_sequence : dynamic_sequences) {
    Fence fence;
    fence.epoch = durable_epoch;
    fence.boot = durable_boot;
    fence.domain = AuthorityDomain::FABRIC_STATE;
    fence.minimum_generation = Generation{recovered_sequence.value};
    fence.sequence = recovered_sequence;
    fence.reason = "process restart fenced a dynamic record recovered from sequence " +
                   std::to_string(recovered_sequence.value);
    Status status = store->record_fence(std::move(fence));
    if (!status.ok()) return status;
    ++fenced;
  }
  report.fenced_dynamic_records = fenced;
  if (fenced > 0) {
    Explanation explanation;
    explanation.code = ReasonCode::PERSISTENCE_STALE_DYNAMIC_STATE_FENCED;
    explanation.detail_a = fenced;
    explanation.text =
        "recovered attempts and observations are fenced and are not restored as live state";
    report.explanations.push_back(explanation);
  }
  {
    const std::vector<std::uint8_t> payload =
        encode_epoch_payload(durable_epoch, durable_boot, store->epoch_, store->boot_);
    Status status = store->append(RecordType::BOOT, payload, nullptr);
    if (!status.ok()) return status;
  }
  {
    Explanation explanation;
    explanation.code = ReasonCode::PERSISTENCE_EPOCH_ADVANCED;
    explanation.detail_a = durable_epoch.value();
    explanation.detail_b = store->epoch_.value();
    explanation.text = "coordinator epoch and boot incarnation advance on every open";
    report.explanations.push_back(explanation);
  }
  return std::unique_ptr<DurableStore>(store.release());
}

Status DurableStore::append(RecordType type,
                            const std::vector<std::uint8_t>& payload,
                            Sequence* out,
                            bool flush_now) {
  if (closed_) return Status::error(StatusCode::CLOSED, "store is closed");
  if (!is_valid(type)) {
    return Status::error(StatusCode::INVALID_ARGUMENT, "record type is outside the domain");
  }
  if (payload.size() > limits_.max_record_bytes) {
    return Status::error(StatusCode::EXHAUSTED, "record payload exceeds the configured bound");
  }
  if (records_.size() >= limits_.max_records) {
    return Status::error(StatusCode::EXHAUSTED, "durable record count bound reached");
  }
  const Sequence sequence{last_sequence_.value + 1};
  const std::vector<std::uint8_t> bytes = frame_record(type, sequence, epoch_, payload);
  std::FILE* file = static_cast<std::FILE*>(file_);
  if (file == nullptr) return Status::error(StatusCode::CLOSED, "store has no journal handle");
  if (std::fwrite(bytes.data(), 1, bytes.size(), file) != bytes.size()) {
    return Status::error(StatusCode::IO_ERROR, "journal write failed");
  }
  if (flush_now) {
    const Status flushed = flush_file(file);
    if (!flushed.ok()) return flushed;
  }
  DurableRecord record;
  record.type = type;
  record.sequence = sequence;
  record.payload = payload;
  records_.push_back(std::move(record));
  last_sequence_ = sequence;
  if (out != nullptr) *out = sequence;
  return Status::success();
}

Status DurableStore::record_fence(Fence fence) {
  CanonicalWriter writer;
  encode_fence(fence, writer);
  const Status status = append(RecordType::FENCE, writer.buffer(), nullptr);
  if (status.ok()) fences_.push_back(std::move(fence));
  return status;
}

Status DurableStore::commit_snapshot() {
  if (closed_) return Status::error(StatusCode::CLOSED, "store is closed");
  std::vector<std::uint8_t> payload;
  for (const DurableRecord& record : records_) {
    const std::vector<std::uint8_t> framed = frame_record(record.type, record.sequence, epoch_,
                                                          record.payload);
    payload.insert(payload.end(), framed.begin(), framed.end());
  }
  std::vector<std::uint8_t> bytes(kSnapshotHeaderSize + payload.size(), 0);
  std::uint8_t* header = bytes.data();
  write_u32(header, kSnapshotMagic);
  write_u16(header + 4, static_cast<std::uint16_t>(kPersistenceFormatVersion));
  write_u16(header + 6, 0);
  write_u32(header + 8, static_cast<std::uint32_t>(records_.size()));
  write_u32(header + 12, static_cast<std::uint32_t>(payload.size()));
  write_u32(header + 16, detail::crc32(payload.data(), payload.size()));
  write_u64(header + 20, last_sequence_.value);
  write_u64(header + 28, epoch_.value());
  write_u32(header + 36, detail::crc32(header, 36));
  if (!payload.empty()) std::memcpy(header + kSnapshotHeaderSize, payload.data(), payload.size());

  const std::string temporary = snapshot_path_ + ".tmp";
  {
    std::FILE* file = std::fopen(temporary.c_str(), "wb");
    if (file == nullptr) {
      return Status::error(StatusCode::IO_ERROR, "cannot create the temporary snapshot");
    }
    const std::size_t written = std::fwrite(bytes.data(), 1, bytes.size(), file);
    Status status = written == bytes.size()
                        ? flush_file(file)
                        : Status::error(StatusCode::IO_ERROR, "snapshot write failed");
    std::fclose(file);
    if (!status.ok()) {
      std::error_code ec;
      std::filesystem::remove(temporary, ec);
      return status;
    }
  }
  std::error_code ec;
#ifdef _WIN32
  if (!MoveFileExA(temporary.c_str(), snapshot_path_.c_str(),
                   MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    std::filesystem::remove(temporary, ec);
    return Status::error(StatusCode::IO_ERROR, "transactional snapshot replacement failed");
  }
#else
  if (std::rename(temporary.c_str(), snapshot_path_.c_str()) != 0) {
    std::filesystem::remove(temporary, ec);
    return Status::error(StatusCode::IO_ERROR, "transactional snapshot replacement failed");
  }
#endif
  // Only after the snapshot is durably installed is the journal reset.
  std::FILE* file = static_cast<std::FILE*>(file_);
  if (file != nullptr) {
    std::fclose(file);
    file_ = nullptr;
  }
  {
    std::FILE* truncated = std::fopen(path_.c_str(), "wb");
    if (truncated == nullptr) {
      return Status::error(StatusCode::IO_ERROR, "cannot reset the journal after the snapshot");
    }
    Status status = flush_file(truncated);
    std::fclose(truncated);
    if (!status.ok()) return status;
  }
  std::FILE* reopened = std::fopen(path_.c_str(), "ab");
  if (reopened == nullptr) {
    return Status::error(StatusCode::IO_ERROR, "cannot reopen the journal after the snapshot");
  }
  file_ = reopened;
  return Status::success();
}

}  // namespace nrp
