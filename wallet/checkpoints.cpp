// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/assign/list_of.hpp> // for 'map_list_of()'
#include <boost/foreach.hpp>

#include "chainparams.h"
#include "checkpoints.h"

#include "ThreadSafeMap.h"

#include "main.h"
#include "txdb.h"
#include "uint256.h"

static const int nCheckpointSpan = 10;

namespace Checkpoints {

bool CheckHardened(int nHeight, const uint256& hash)
{
    const MapCheckpoints& checkpoints = Params().Checkpoints();

    uint256 foundHash(0);
    bool    found = checkpoints.get(nHeight, foundHash);
    if (!found)
        return true;
    return hash == foundHash;
}

int GetTotalBlocksEstimate()
{
    const MapCheckpoints& checkpoints = Params().Checkpoints();

    MapCheckpoints::value_type r;
    if (checkpoints.back(r)) {
        return r.first;
    } else {
        return 0;
    }
}

CBlockIndex* GetLastCheckpoint(const std::map<uint256, CBlockIndex*>& mapBlockIndex)
{
    const MapCheckpoints::MapType checkpoints = Params().Checkpoints().getInternalMap();

    BOOST_REVERSE_FOREACH(const MapCheckpoints::MapType::value_type& i, checkpoints)
    {
        const uint256&                                  hash = i.second;
        std::map<uint256, CBlockIndex*>::const_iterator t    = mapBlockIndex.find(hash);
        if (t != mapBlockIndex.end())
            return t->second;
    }
    return NULL;
}

// ppcoin: synchronized checkpoint (centrally broadcasted)
uint256          hashSyncCheckpoint    = 0;
uint256          hashPendingCheckpoint = 0;
CSyncCheckpoint  checkpointMessage;
CSyncCheckpoint  checkpointMessagePending;
uint256          hashInvalidCheckpoint = 0;
CCriticalSection cs_hashSyncCheckpoint;

// ppcoin: get last synchronized checkpoint
CBlockIndex* GetLastSyncCheckpoint()
{
    LOCK(cs_hashSyncCheckpoint);
    if (!mapBlockIndex.count(hashSyncCheckpoint))
        error("GetSyncCheckpoint: block index missing for current sync-checkpoint %s",
              hashSyncCheckpoint.ToString().c_str());
    else
        return boost::atomic_load(&mapBlockIndex[hashSyncCheckpoint]).get();
    return NULL;
}

// ppcoin: only descendant of current sync-checkpoint is allowed
bool ValidateSyncCheckpoint(uint256 hashCheckpoint)
{
    if (!mapBlockIndex.count(hashSyncCheckpoint))
        return error("ValidateSyncCheckpoint: block index missing for current sync-checkpoint %s",
                     hashSyncCheckpoint.ToString().c_str());
    if (!mapBlockIndex.count(hashCheckpoint))
        return error("ValidateSyncCheckpoint: block index missing for received sync-checkpoint %s",
                     hashCheckpoint.ToString().c_str());

    CBlockIndexSmartPtr pindexSyncCheckpoint = boost::atomic_load(&mapBlockIndex[hashSyncCheckpoint]);
    CBlockIndexSmartPtr pindexCheckpointRecv = boost::atomic_load(&mapBlockIndex[hashCheckpoint]);

    if (pindexCheckpointRecv->nHeight <= pindexSyncCheckpoint->nHeight) {
        // Received an older checkpoint, trace back from current checkpoint
        // to the same height of the received checkpoint to verify
        // that current checkpoint should be a descendant block
        CBlockIndexSmartPtr pindex = pindexSyncCheckpoint;
        while (pindex->nHeight > pindexCheckpointRecv->nHeight)
            if (!(pindex = pindex->pprev))
                return error("ValidateSyncCheckpoint: pprev null - block index structure failure");
        if (pindex->GetBlockHash() != hashCheckpoint) {
            hashInvalidCheckpoint = hashCheckpoint;
            return error("ValidateSyncCheckpoint: new sync-checkpoint %s is conflicting with current "
                         "sync-checkpoint %s",
                         hashCheckpoint.ToString().c_str(), hashSyncCheckpoint.ToString().c_str());
        }
        return false; // ignore older checkpoint
    }

    // Received checkpoint should be a descendant block of the current
    // checkpoint. Trace back to the same height of current checkpoint
    // to verify.
    CBlockIndexSmartPtr pindex = pindexCheckpointRecv;
    while (pindex->nHeight > pindexSyncCheckpoint->nHeight)
        if (!(pindex = pindex->pprev))
            return error("ValidateSyncCheckpoint: pprev2 null - block index structure failure");
    if (pindex->GetBlockHash() != hashSyncCheckpoint) {
        hashInvalidCheckpoint = hashCheckpoint;
        return error("ValidateSyncCheckpoint: new sync-checkpoint %s is not a descendant of current "
                     "sync-checkpoint %s",
                     hashCheckpoint.ToString().c_str(), hashSyncCheckpoint.ToString().c_str());
    }
    return true;
}

bool WriteSyncCheckpoint(const uint256& hashCheckpoint)
{
    CTxDB txdb;
    txdb.TxnBegin();
    if (!txdb.WriteSyncCheckpoint(hashCheckpoint)) {
        txdb.TxnAbort();
        return error("WriteSyncCheckpoint(): failed to write to db sync checkpoint %s",
                     hashCheckpoint.ToString().c_str());
    }
    if (!txdb.TxnCommit())
        return error("WriteSyncCheckpoint(): failed to commit to db sync checkpoint %s",
                     hashCheckpoint.ToString().c_str());

    Checkpoints::hashSyncCheckpoint = hashCheckpoint;
    return true;
}

bool AcceptPendingSyncCheckpoint()
{
    LOCK(cs_hashSyncCheckpoint);
    if (hashPendingCheckpoint != 0 && mapBlockIndex.count(hashPendingCheckpoint)) {
        if (!ValidateSyncCheckpoint(hashPendingCheckpoint)) {
            hashPendingCheckpoint = 0;
            checkpointMessagePending.SetNull();
            return false;
        }

        CTxDB               txdb;
        CBlockIndexSmartPtr pindexCheckpoint = boost::atomic_load(&mapBlockIndex[hashPendingCheckpoint]);
        if (!pindexCheckpoint->IsInMainChain()) {
            CBlock block;
            if (!block.ReadFromDisk(pindexCheckpoint.get()))
                return error("AcceptPendingSyncCheckpoint: ReadFromDisk failed for sync checkpoint %s",
                             hashPendingCheckpoint.ToString().c_str());
            if (!block.SetBestChain(txdb, pindexCheckpoint)) {
                hashInvalidCheckpoint = hashPendingCheckpoint;
                return error("AcceptPendingSyncCheckpoint: SetBestChain failed for sync checkpoint %s",
                             hashPendingCheckpoint.ToString().c_str());
            }
        }

        if (!WriteSyncCheckpoint(hashPendingCheckpoint))
            return error("AcceptPendingSyncCheckpoint(): failed to write sync checkpoint %s",
                         hashPendingCheckpoint.ToString().c_str());
        hashPendingCheckpoint = 0;
        checkpointMessage     = checkpointMessagePending;
        checkpointMessagePending.SetNull();
        printf("AcceptPendingSyncCheckpoint : sync-checkpoint at %s\n",
               hashSyncCheckpoint.ToString().c_str());
        // relay the checkpoint
        if (!checkpointMessage.IsNull()) {
            for (CNode* pnode : vNodes)
                checkpointMessage.RelayTo(pnode);
        }
        return true;
    }
    return false;
}

// Automatically select a suitable sync-checkpoint
uint256 AutoSelectSyncCheckpoint()
{
    ConstCBlockIndexSmartPtr pindex = boost::atomic_load(&pindexBest);
    // Search backward for a block within max span and maturity window
    unsigned int nTS = Params().TargetSpacing();
    while (pindex->pprev &&
           (pindex->GetBlockTime() + nCheckpointSpan * nTS >
                boost::atomic_load(&pindexBest)->GetBlockTime() ||
            pindex->nHeight + nCheckpointSpan > boost::atomic_load(&pindexBest)->nHeight)) {
        pindex = pindex->pprev;
    }
    return pindex->GetBlockHash();
}

// Check against synchronized checkpoint
bool CheckSync(const uint256& hashBlock, const CBlockIndex* pindexPrev)
{
    int nHeight = pindexPrev->nHeight + 1;

    LOCK(cs_hashSyncCheckpoint);
    // sync-checkpoint should always be accepted block
    assert(mapBlockIndex.count(hashSyncCheckpoint));
    const CBlockIndex* pindexSync = boost::atomic_load(&mapBlockIndex[hashSyncCheckpoint]).get();

    if (nHeight > pindexSync->nHeight) {
        // trace back to same height as sync-checkpoint
        const CBlockIndex* pindex = pindexPrev;
        while (pindex->nHeight > pindexSync->nHeight)
            if (!(pindex = pindex->pprev.get()))
                return error("CheckSync: pprev null - block index structure failure");
        if (pindex->nHeight < pindexSync->nHeight || pindex->GetBlockHash() != hashSyncCheckpoint)
            return false; // only descendant of sync-checkpoint can pass check
    }
    if (nHeight == pindexSync->nHeight && hashBlock != hashSyncCheckpoint)
        return false; // same height with sync-checkpoint
    if (nHeight < pindexSync->nHeight && !mapBlockIndex.count(hashBlock))
        return false; // lower height than sync-checkpoint
    return true;
}

bool WantedByPendingSyncCheckpoint(uint256 hashBlock)
{
    LOCK(cs_hashSyncCheckpoint);
    if (hashPendingCheckpoint == 0)
        return false;
    if (hashBlock == hashPendingCheckpoint)
        return true;
    if (mapOrphanBlocks.count(hashPendingCheckpoint) &&
        hashBlock == WantedByOrphan(mapOrphanBlocks[hashPendingCheckpoint]))
        return true;
    return false;
}

// ppcoin: reset synchronized checkpoint to last hardened checkpoint
bool ResetSyncCheckpoint()
{
    LOCK(cs_hashSyncCheckpoint);
    MapCheckpoints::MapType mapCheckpointsCopy = Params().Checkpoints().getInternalMap();
    const uint256&          hash               = mapCheckpointsCopy.rbegin()->second;
    if (mapBlockIndex.count(hash) && !mapBlockIndex[hash]->IsInMainChain()) {
        // checkpoint block accepted but not yet in main chain
        printf("ResetSyncCheckpoint: SetBestChain to hardened checkpoint %s\n", hash.ToString().c_str());
        CTxDB  txdb;
        CBlock block;
        if (!block.ReadFromDisk(boost::atomic_load(&mapBlockIndex[hash]).get()))
            return error("ResetSyncCheckpoint: ReadFromDisk failed for hardened checkpoint %s",
                         hash.ToString().c_str());
        if (!block.SetBestChain(txdb, boost::atomic_load(&mapBlockIndex[hash]))) {
            return error("ResetSyncCheckpoint: SetBestChain failed for hardened checkpoint %s",
                         hash.ToString().c_str());
        }
    } else if (!mapBlockIndex.count(hash)) {
        // checkpoint block not yet accepted
        hashPendingCheckpoint = hash;
        checkpointMessagePending.SetNull();
        printf("ResetSyncCheckpoint: pending for sync-checkpoint %s\n",
               hashPendingCheckpoint.ToString().c_str());
    }

    BOOST_REVERSE_FOREACH(const MapCheckpoints::MapType::value_type& i, mapCheckpointsCopy)
    {
        const uint256& hash = i.second;
        if (mapBlockIndex.count(hash) && mapBlockIndex[hash]->IsInMainChain()) {
            if (!WriteSyncCheckpoint(hash))
                return error("ResetSyncCheckpoint: failed to write sync checkpoint %s",
                             hash.ToString().c_str());
            printf("ResetSyncCheckpoint: sync-checkpoint reset to %s\n",
                   hashSyncCheckpoint.ToString().c_str());
            return true;
        }
    }

    return false;
}

void AskForPendingSyncCheckpoint(CNode* pfrom)
{
    LOCK(cs_hashSyncCheckpoint);
    if (pfrom && hashPendingCheckpoint != 0 && (!mapBlockIndex.count(hashPendingCheckpoint)) &&
        (!mapOrphanBlocks.count(hashPendingCheckpoint)))
        pfrom->AskFor(CInv(MSG_BLOCK, hashPendingCheckpoint));
}

bool SetCheckpointPrivKey(std::string strPrivKey)
{
    // Test signing a sync-checkpoint with genesis block
    CSyncCheckpoint checkpoint;
    checkpoint.hashCheckpoint = Params().GenesisBlockHash();
    CDataStream sMsg(SER_NETWORK, PROTOCOL_VERSION);
    sMsg << (CUnsignedSyncCheckpoint)checkpoint;
    checkpoint.vchMsg = std::vector<unsigned char>(sMsg.begin(), sMsg.end());

    std::vector<unsigned char> vchPrivKey = ParseHex(strPrivKey);
    CKey                       key;
    key.SetPrivKey(
        CPrivKey(vchPrivKey.begin(), vchPrivKey.end())); // if key is not correct openssl may crash
    if (!key.Sign(Hash(checkpoint.vchMsg.begin(), checkpoint.vchMsg.end()), checkpoint.vchSig))
        return false;

    // Test signing successful, proceed
    CSyncCheckpoint::strMasterPrivKey = strPrivKey;
    return true;
}

bool SendSyncCheckpoint(uint256 hashCheckpoint)
{
    CSyncCheckpoint checkpoint;
    checkpoint.hashCheckpoint = hashCheckpoint;
    CDataStream sMsg(SER_NETWORK, PROTOCOL_VERSION);
    sMsg << (CUnsignedSyncCheckpoint)checkpoint;
    checkpoint.vchMsg = std::vector<unsigned char>(sMsg.begin(), sMsg.end());

    if (CSyncCheckpoint::strMasterPrivKey.empty())
        return error("SendSyncCheckpoint: Checkpoint master key unavailable.");
    std::vector<unsigned char> vchPrivKey = ParseHex(CSyncCheckpoint::strMasterPrivKey);
    CKey                       key;
    key.SetPrivKey(
        CPrivKey(vchPrivKey.begin(), vchPrivKey.end())); // if key is not correct openssl may crash
    if (!key.Sign(Hash(checkpoint.vchMsg.begin(), checkpoint.vchMsg.end()), checkpoint.vchSig))
        return error("SendSyncCheckpoint: Unable to sign checkpoint, check private key?");

    if (!checkpoint.ProcessSyncCheckpoint(NULL)) {
        printf("WARNING: SendSyncCheckpoint: Failed to process checkpoint.\n");
        return false;
    }

    // Relay checkpoint
    {
        LOCK(cs_vNodes);
        for (CNode* pnode : vNodes)
            checkpoint.RelayTo(pnode);
    }
    return true;
}

// Is the sync-checkpoint outside maturity window?
bool IsMatureSyncCheckpoint()
{
    LOCK(cs_hashSyncCheckpoint);
    // sync-checkpoint should always be accepted block
    assert(mapBlockIndex.count(hashSyncCheckpoint));
    int                nCbM       = Params().CoinbaseMaturity();
    unsigned int       nSMA       = Params().StakeMinAge();
    const CBlockIndex* pindexSync = boost::atomic_load(&mapBlockIndex[hashSyncCheckpoint]).get();
    return (nBestHeight >= pindexSync->nHeight + nCbM ||
            pindexSync->GetBlockTime() + nSMA < GetAdjustedTime());
}

int64_t GetLastCheckpointBlockHeight()
{
    MapCheckpoints::value_type lastValue;
    if (Params().Checkpoints().back(lastValue)) {
        return lastValue.first;
    } else {
        return 0;
    }
}

} // namespace Checkpoints

// ppcoin: sync-checkpoint master key
const std::string CSyncCheckpoint::strMasterPubKey = "04a18357665ed7a802dcf252ef528d3dc786da38653b51d1ab"
                                                     "8e9f4820b55aca807892a056781967315908ac205940ec9d6f"
                                                     "2fd0a85941966971eac7e475a27826";

std::string CSyncCheckpoint::strMasterPrivKey = "";

// ppcoin: verify signature of sync-checkpoint message
bool CSyncCheckpoint::CheckSignature()
{
    CKey key;
    if (!key.SetPubKey(ParseHex(CSyncCheckpoint::strMasterPubKey)))
        return error("CSyncCheckpoint::CheckSignature() : SetPubKey failed");
    if (!key.Verify(Hash(vchMsg.begin(), vchMsg.end()), vchSig))
        return error("CSyncCheckpoint::CheckSignature() : verify signature failed");

    // Now unserialize the data
    CDataStream sMsg(vchMsg, SER_NETWORK, PROTOCOL_VERSION);
    sMsg >> *(CUnsignedSyncCheckpoint*)this;
    return true;
}

// ppcoin: process synchronized checkpoint
bool CSyncCheckpoint::ProcessSyncCheckpoint(CNode* pfrom)
{
    if (!CheckSignature())
        return false;

    LOCK(Checkpoints::cs_hashSyncCheckpoint);
    if (!mapBlockIndex.count(hashCheckpoint)) {
        // We haven't received the checkpoint chain, keep the checkpoint as pending
        Checkpoints::hashPendingCheckpoint    = hashCheckpoint;
        Checkpoints::checkpointMessagePending = *this;
        printf("ProcessSyncCheckpoint: pending for sync-checkpoint %s\n",
               hashCheckpoint.ToString().c_str());
        // Ask this guy to fill in what we're missing
        if (pfrom) {
            pfrom->PushGetBlocks(pindexBest.get(), hashCheckpoint);
            // ask directly as well in case rejected earlier by duplicate
            // proof-of-stake because getblocks may not get it this time
            pfrom->AskFor(CInv(MSG_BLOCK, mapOrphanBlocks.count(hashCheckpoint)
                                              ? WantedByOrphan(mapOrphanBlocks[hashCheckpoint])
                                              : hashCheckpoint));
        }
        return false;
    }

    if (!Checkpoints::ValidateSyncCheckpoint(hashCheckpoint))
        return false;

    CTxDB               txdb;
    CBlockIndexSmartPtr pindexCheckpoint = boost::atomic_load(&mapBlockIndex[hashCheckpoint]);
    if (!pindexCheckpoint->IsInMainChain()) {
        // checkpoint chain received but not yet main chain
        CBlock block;
        if (!block.ReadFromDisk(pindexCheckpoint.get()))
            return error("ProcessSyncCheckpoint: ReadFromDisk failed for sync checkpoint %s",
                         hashCheckpoint.ToString().c_str());
        if (!block.SetBestChain(txdb, pindexCheckpoint)) {
            Checkpoints::hashInvalidCheckpoint = hashCheckpoint;
            return error("ProcessSyncCheckpoint: SetBestChain failed for sync checkpoint %s",
                         hashCheckpoint.ToString().c_str());
        }
    }

    if (!Checkpoints::WriteSyncCheckpoint(hashCheckpoint))
        return error("ProcessSyncCheckpoint(): failed to write sync checkpoint %s",
                     hashCheckpoint.ToString().c_str());
    Checkpoints::checkpointMessage     = *this;
    Checkpoints::hashPendingCheckpoint = 0;
    Checkpoints::checkpointMessagePending.SetNull();
    printf("ProcessSyncCheckpoint: sync-checkpoint at %s\n", hashCheckpoint.ToString().c_str());
    return true;
}
