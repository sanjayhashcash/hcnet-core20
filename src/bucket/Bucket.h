#pragma once

// Copyright 2015 Hcnet Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "bucket/BucketIndex.h"
#include "util/NonCopyable.h"
#include "util/ProtocolVersion.h"
#include "xdr/Hcnet-ledger.h"
#include <list>
#include <optional>
#include <string>

namespace asio
{
class io_context;
}

namespace medida
{
class Counter;
class Meter;
}

namespace hcnet
{

/**
 * Bucket is an immutable container for a sorted set of "Entries" (object ID,
 * hash, xdr-message tuples) which is designed to be held in a shared_ptr<>
 * which is referenced between threads, to minimize copying. It is therefore
 * imperative that it be _really_ immutable, not just faking it.
 *
 * Two buckets can be merged together efficiently (in a single pass): elements
 * from the newer bucket overwrite elements from the older bucket, the rest are
 * merged in sorted order, and all elements are hashed while being added.
 */

class AbstractLedgerTxn;
class Application;
class BucketManager;
class SearchableBucketListSnapshot;
struct EvictionResultEntry;
class EvictionStatistics;

class Bucket : public std::enable_shared_from_this<Bucket>,
               public NonMovableOrCopyable
{
    std::filesystem::path const mFilename;
    Hash const mHash;
    size_t mSize{0};

    std::unique_ptr<BucketIndex const> mIndex{};

    // Returns index, throws if index not yet initialized
    BucketIndex const& getIndex() const;

    static std::string randomFileName(std::string const& tmpDir,
                                      std::string ext);

  public:
    // Create an empty bucket. The empty bucket has hash '000000...' and its
    // filename is the empty string.
    Bucket();

    // Construct a bucket with a given filename and hash. Asserts that the file
    // exists, but does not check that the hash is the bucket's hash. Caller
    // needs to ensure that.
    Bucket(std::string const& filename, Hash const& hash,
           std::unique_ptr<BucketIndex const>&& index);

    Hash const& getHash() const;
    std::filesystem::path const& getFilename() const;
    size_t getSize() const;

    // Returns true if a BucketEntry that is key-wise identical to the given
    // BucketEntry exists in the bucket. For testing.
    bool containsBucketIdentity(BucketEntry const& id) const;

    bool isEmpty() const;

    // Delete index and close file stream
    void freeIndex();

    // Returns true if bucket is indexed, false otherwise
    bool isIndexed() const;

    // Returns [lowerBound, upperBound) of file offsets for all offers in the
    // bucket, or std::nullopt if no offers exist
    std::optional<std::pair<std::streamoff, std::streamoff>>
    getOfferRange() const;

    // Sets index, throws if index is already set
    void setIndex(std::unique_ptr<BucketIndex const>&& index);

    // At version 11, we added support for INITENTRY and METAENTRY. Before this
    // we were only supporting LIVEENTRY and DEADENTRY.
    static constexpr ProtocolVersion
        FIRST_PROTOCOL_SUPPORTING_INITENTRY_AND_METAENTRY =
            ProtocolVersion::V_11;
    static constexpr ProtocolVersion FIRST_PROTOCOL_SHADOWS_REMOVED =
        ProtocolVersion::V_12;

    static void checkProtocolLegality(BucketEntry const& entry,
                                      uint32_t protocolVersion);

    static std::vector<BucketEntry>
    convertToBucketEntry(bool useInit,
                         std::vector<LedgerEntry> const& initEntries,
                         std::vector<LedgerEntry> const& liveEntries,
                         std::vector<LedgerKey> const& deadEntries);

    static std::string randomBucketName(std::string const& tmpDir);
    static std::string randomBucketIndexName(std::string const& tmpDir);

#ifdef BUILD_TESTS
    // "Applies" the bucket to the database. For each entry in the bucket,
    // if the entry is init or live, creates or updates the corresponding
    // entry in the database (respectively; if the entry is dead (a
    // tombstone), deletes the corresponding entry in the database.
    void apply(Application& app) const;

    BucketIndex const&
    getIndexForTesting() const
    {
        return getIndex();
    }

#endif // BUILD_TESTS

    // Returns false if eof reached, true otherwise. Modifies iter as the bucket
    // is scanned. Also modifies bytesToScan and maxEntriesToEvict such that
    // after this function returns:
    // bytesToScan -= amount_bytes_scanned
    // maxEntriesToEvict -= entries_evicted
    bool scanForEvictionLegacy(AbstractLedgerTxn& ltx, EvictionIterator& iter,
                               uint32_t& bytesToScan,
                               uint32_t& remainingEntriesToEvict,
                               uint32_t ledgerSeq,
                               medida::Counter& entriesEvictedCounter,
                               medida::Counter& bytesScannedForEvictionCounter,
                               std::shared_ptr<EvictionStatistics> stats) const;

    bool scanForEviction(EvictionIterator& iter, uint32_t& bytesToScan,
                         uint32_t ledgerSeq,
                         std::list<EvictionResultEntry>& evictableKeys,
                         SearchableBucketListSnapshot& bl) const;

    // Create a fresh bucket from given vectors of init (created) and live
    // (updated) LedgerEntries, and dead LedgerEntryKeys. The bucket will
    // be sorted, hashed, and adopted in the provided BucketManager.
    static std::shared_ptr<Bucket>
    fresh(BucketManager& bucketManager, uint32_t protocolVersion,
          std::vector<LedgerEntry> const& initEntries,
          std::vector<LedgerEntry> const& liveEntries,
          std::vector<LedgerKey> const& deadEntries, bool countMergeEvents,
          asio::io_context& ctx, bool doFsync);

    // Merge two buckets together, producing a fresh one. Entries in `oldBucket`
    // are overridden in the fresh bucket by keywise-equal entries in
    // `newBucket`. Entries are inhibited from the fresh bucket by keywise-equal
    // entries in any of the buckets in the provided `shadows` vector.
    //
    // Each bucket is self-describing in terms of the ledger protocol version it
    // was constructed under, and the merge algorithm adjusts to the maximum of
    // the versions attached to each input or shadow bucket. The provided
    // `maxProtocolVersion` bounds this (for error checking) and should usually
    // be the protocol of the ledger header at which the merge is starting. An
    // exception will be thrown if any provided bucket versions exceed it.
    static std::shared_ptr<Bucket>
    merge(BucketManager& bucketManager, uint32_t maxProtocolVersion,
          std::shared_ptr<Bucket> const& oldBucket,
          std::shared_ptr<Bucket> const& newBucket,
          std::vector<std::shared_ptr<Bucket>> const& shadows,
          bool keepDeadEntries, bool countMergeEvents, asio::io_context& ctx,
          bool doFsync);

    static uint32_t getBucketVersion(std::shared_ptr<Bucket> const& bucket);
    static uint32_t
    getBucketVersion(std::shared_ptr<Bucket const> const& bucket);

    friend class BucketSnapshot;
};
}
