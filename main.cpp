// Copyright (c) 2008 Satoshi Nakamoto
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. IN NO EVENT
// SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

#include "headers.h"
#include "sha.h"





//
// Global state
//

map<uint256, CTransaction> mapTransactions;
CCriticalSection cs_mapTransactions;
unsigned int nTransactionsUpdated = 0;
/// mapNextTx is only used anymore to track disk tx outpoints used by memory txes
map<COutPoint, CInPoint> mapNextTx;

map<uint256, CBlockIndex*> mapBlockIndex;
const uint256 hashGenesisBlock("0x000006b15d1327d67e971d1de9116bd60a3a01556c91b6ebaa416ebc0cfaa646");
CBlockIndex* pindexGenesisBlock = NULL;
int nBestHeight = -1;
uint256 hashTimeChainBest = 0;
CBlockIndex* pindexBest = NULL;

map<uint256, CBlock*> mapOrphanBlocks;
multimap<uint256, CBlock*> mapOrphanBlocksByPrev;

map<uint256, CWalletTx> mapWallet;
vector<pair<uint256, bool> > vWalletUpdated;
CCriticalSection cs_mapWallet;

map<vector<unsigned char>, CPrivKey> mapKeys;
map<uint160, vector<unsigned char> > mapPubKeys;
CCriticalSection cs_mapKeys;
CKey keyUser;

int fGenerateBitcoins;












//////////////////////////////////////////////////////////////////////////////
//
// mapKeys
//

bool AddKey(const CKey& key)
{
    CRITICAL_BLOCK(cs_mapKeys)
    {
        mapKeys[key.GetPubKey()] = key.GetPrivKey();
        mapPubKeys[Hash160(key.GetPubKey())] = key.GetPubKey();
    }
    return CWalletDB().WriteKey(key.GetPubKey(), key.GetPrivKey());
}

vector<unsigned char> GenerateNewKey()
{
    CKey key;
    key.MakeNewKey();
    if (!AddKey(key))
        throw runtime_error("GenerateNewKey() : AddKey failed\n");
    return key.GetPubKey();
}




//////////////////////////////////////////////////////////////////////////////
//
// mapWallet
//

bool AddToWallet(const CWalletTx& wtxIn)
{
    uint256 hash = wtxIn.GetHash();
    CRITICAL_BLOCK(cs_mapWallet)
    {
        // Inserts only if not already there, returns tx inserted or tx found
        pair<map<uint256, CWalletTx>::iterator, bool> ret = mapWallet.insert(make_pair(hash, wtxIn));
        CWalletTx& wtx = (*ret.first).second;
        bool fInsertedNew = ret.second;

        //// debug print
        printf("AddToWallet %s  %d\n", wtxIn.GetHash().ToString().c_str(), fInsertedNew);

        if (!fInsertedNew)
        {
            // Merge
            bool fUpdated = false;
            if (wtxIn.hashBlock != 0 && wtxIn.hashBlock != wtx.hashBlock)
            {
                wtx.hashBlock = wtxIn.hashBlock;
                fUpdated = true;
            }
            if (wtxIn.fFromMe && wtxIn.fFromMe != wtx.fFromMe)
            {
                wtx.fFromMe = wtxIn.fFromMe;
                fUpdated = true;
            }
            if (wtxIn.fSpent && wtxIn.fSpent != wtx.fSpent)
            {
                wtx.fSpent = wtxIn.fSpent;
                fUpdated = true;
            }
            if (!fUpdated)
                return true;
        }

        // Write to disk
        if (!wtx.WriteToDisk())
            return false;

        // Notify UI
        vWalletUpdated.push_back(make_pair(hash, fInsertedNew));
    }

    // Refresh UI
    MainFrameRepaint();
    return true;
}

bool AddToWalletIfMine(const CTransaction& tx, const CBlock* pblock)
{
    if (tx.IsMine())
    {
        CWalletTx wtx(tx);
        if (pblock)
        {
            wtx.hashBlock = pblock->GetHash();
            wtx.nTime = pblock->nTime;
        }
        else
        {
            wtx.nTime = GetAdjustedTime();
        }
        return AddToWallet(wtx);
    }
    return true;
}

void ReacceptWalletTransactions()
{
    // Reaccept any txes of ours that aren't already in a block
    CRITICAL_BLOCK(cs_mapWallet)
    {
        CTxDB txdb("r");
        foreach(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
        {
            CWalletTx& wtx = item.second;
            if (!txdb.ContainsTx(wtx.GetHash()))
                wtx.AcceptWalletTransaction(txdb, false);
        }
    }
}

void RelayWalletTransactions()
{
    static int64 nLastTime;
    if (GetTime() - nLastTime < 15 * 60)
        return;
    nLastTime = GetTime();

    // Rebroadcast any of our txes that aren't in a block yet
    CRITICAL_BLOCK(cs_mapWallet)
    {
        CTxDB txdb("r");
        foreach(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
            item.second.RelayWalletTransaction(txdb);
    }
}











//////////////////////////////////////////////////////////////////////////////
//
// CTransaction
//

bool CTxIn::IsMine() const
{
    map<uint256, CWalletTx>::iterator mi = mapWallet.find(prevout.hash);
    if (mi != mapWallet.end())
    {
        const CWalletTx& prev = (*mi).second;
        if (prevout.n < prev.vout.size())
            if (prev.vout[prevout.n].IsMine())
                return true;
    }
    return false;
}

int64 CTxIn::GetDebit() const
{
    map<uint256, CWalletTx>::iterator mi = mapWallet.find(prevout.hash);
    if (mi != mapWallet.end())
    {
        const CWalletTx& prev = (*mi).second;
        if (prevout.n < prev.vout.size())
            if (prev.vout[prevout.n].IsMine())
                return prev.vout[prevout.n].nValue;
    }
    return 0;
}




int CMerkleTx::SetMerkleBranch()
{
    if (fClient)
    {
        if (hashBlock == 0)
            return 0;
    }
    else
    {
        // Load the block this tx is in
        CDiskTxPos pos;
        if (!CTxDB("r").ReadTxPos(GetHash(), pos))
            return 0;
        CBlock block;
        if (!block.ReadFromDisk(pos.nFile, pos.nBlockPos, true))
            return 0;

        // Update the tx's hashBlock
        hashBlock = block.GetHash();

        // Locate the transaction
        for (nIndex = 0; nIndex < block.vtx.size(); nIndex++)
            if (block.vtx[nIndex] == *(CTransaction*)this)
                break;
        if (nIndex == block.vtx.size())
        {
            vMerkleBranch.clear();
            nIndex = -1;
            printf("ERROR: SetMerkleBranch() : couldn't find tx in block\n");
            return 0;
        }

        // Fill in merkle branch
        vMerkleBranch = block.GetMerkleBranch(nIndex);
    }

    // Is the tx in a block that's in the main chain
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain())
        return 0;

    return pindexBest->nHeight - pindex->nHeight + 1;
}

void CWalletTx::AddSupportingTransactions(CTxDB& txdb)
{
    vtxPrev.clear();

    const int COPY_DEPTH = 3;
    if (SetMerkleBranch() < COPY_DEPTH)
    {
        vector<uint256> vWorkQueue;
        foreach(const CTxIn& txin, vin)
            vWorkQueue.push_back(txin.prevout.hash);

        map<uint256, const CMerkleTx*> mapWalletPrev;
        set<uint256> setAlreadyDone;
        for (int i = 0; i < vWorkQueue.size(); i++)
        {
            uint256 hash = vWorkQueue[i];
            if (setAlreadyDone.count(hash))
                continue;
            setAlreadyDone.insert(hash);

            CMerkleTx tx;
            if (mapWallet.count(hash))
            {
                tx = mapWallet[hash];
                foreach(const CMerkleTx& txWalletPrev, mapWallet[hash].vtxPrev)
                    mapWalletPrev[txWalletPrev.GetHash()] = &txWalletPrev;
            }
            else if (mapWalletPrev.count(hash))
            {
                tx = *mapWalletPrev[hash];
            }
            else if (!fClient && txdb.ReadDiskTx(hash, tx))
            {
                ;
            }
            else
            {
                printf("ERROR: AddSupportingTransactions() : unsupported transaction\n");
                continue;
            }

            int nDepth = tx.SetMerkleBranch();
            vtxPrev.push_back(tx);

            if (nDepth < COPY_DEPTH)
                foreach(const CTxIn& txin, tx.vin)
                    vWorkQueue.push_back(txin.prevout.hash);
        }
    }

    reverse(vtxPrev.begin(), vtxPrev.end());
}










bool CTransaction::DisconnectInputs(CTxDB& txdb, map<uint256, CTransaction>& mapTestPool, bool fTest)
{
    // Relinquish previous transactions' posNext pointers
    if (!IsCoinBase())
    {
        foreach(const CTxIn& txin, vin)
        {
            COutPoint prevout = txin.prevout;

            CAutoFile fileout = NULL;
            CTransaction txPrevBuf;
            CTransaction& txPrev = (fTest ? mapTestPool[prevout.hash] : txPrevBuf);
            if (txPrev.IsNull())
            {
                // Get prev tx from disk
                // Version -1 tells unserialize to set version so we write back same version
                fileout.SetVersion(-1);
                if (!txdb.ReadDiskTx(prevout.hash, txPrev, &fileout))
                    return false;
            }

            if (prevout.n >= txPrev.vout.size())
                return false;

            // Relinquish posNext pointer
            txPrev.vout[prevout.n].posNext.SetNull();

            // Write back
            if (!fTest)
                fileout << txPrev;
        }
    }

    if (fTest)
    {
        // Put a blocked-off copy of this transaction in the test pool
        CTransaction& txPool = mapTestPool[GetHash()];
        txPool = *this;
        foreach(CTxOut& txout, txPool.vout)
            txout.posNext = CDiskTxPos(1, 1, 1);
    }
    else
    {
        // Remove transaction from index
        if (!txdb.EraseTxPos(*this))
            return false;

        // Resurect single transaction objects
        if (!IsCoinBase())
            AcceptTransaction(txdb, false);
    }

    return true;
}


bool CTransaction::ConnectInputs(CTxDB& txdb, map<uint256, CTransaction>& mapTestPool, CDiskTxPos posThisTx, int nHeight,
                                 bool fTest, bool fMemoryTx, bool fIgnoreDiskConflicts, int64& nFees)
{
    // Take over previous transactions' posNext pointers
    if (!IsCoinBase())
    {
        int64 nValueIn = 0;
        for (int i = 0; i < vin.size(); i++)
        {
            COutPoint prevout = vin[i].prevout;

            CAutoFile fileout = NULL;
            CTransaction txPrevBuf;
            CTransaction& txPrev = (fTest ? mapTestPool[prevout.hash] : txPrevBuf);
            if (txPrev.IsNull() && fTest && fMemoryTx && mapTransactions.count(prevout.hash))
            {
                // Get prev tx from single transactions in memory
                txPrev = mapTransactions[prevout.hash];
            }
            else if (txPrev.IsNull())
            {
                // Get prev tx from disk
                // Version -1 tells unserialize to set version so we write back same version
                fileout.SetVersion(-1);
                if (!txdb.ReadDiskTx(prevout.hash, txPrev, &fileout))
                    return error("ConnectInputs() : prev tx not found");

                // If tx will only be connected in a reorg,
                // then these outpoints will be checked at that time
                if (fIgnoreDiskConflicts)
                    foreach(CTxOut& txout, txPrev.vout)
                        txout.posNext.SetNull();
            }

            if (prevout.n >= txPrev.vout.size())
                return false;

            // Verify signature
            if (!VerifySignature(txPrev, *this, i))
                return error("ConnectInputs() : VerifySignature failed");

            // Check for conflicts
            if (!txPrev.vout[prevout.n].posNext.IsNull())
                return error("ConnectInputs() : prev tx already used");

            // Flag outpoints as used
            txPrev.vout[prevout.n].posNext = posThisTx;

            // Write back
            if (!fTest)
                fileout << txPrev;

            nValueIn += txPrev.vout[prevout.n].nValue;
        }

        // Tally transaction fees
        int64 nTransactionFee = nValueIn - GetValueOut();
        if (nTransactionFee < 0)
            return false;
        nFees += nTransactionFee;
    }

    if (fTest)
    {
        // Add transaction to test pool
        mapTestPool[GetHash()] = *this;
    }
    else
    {
        // Add transaction to disk index
        if (!txdb.WriteTxPos(*this, posThisTx, nHeight))
            return false;

        // Delete redundant single transaction objects
        CRITICAL_BLOCK(cs_mapTransactions)
        {
            foreach(const CTxIn& txin, vin)
                mapNextTx.erase(txin.prevout);
            mapTransactions.erase(GetHash());
        }
    }

    return true;
}




bool CTransaction::AcceptTransaction(CTxDB& txdb, bool fCheckInputs)
{
    // Coinbase is only valid in a block, not as a loose transaction
    if (IsCoinBase())
        return error("AcceptTransaction() : coinbase as individual tx");

    if (!CheckTransaction())
        return error("AcceptTransaction() : CheckTransaction failed");

    uint256 hash = GetHash();
    if (mapTransactions.count(hash))
        return false;

    // Check for conflicts with in-memory transactions
    // and allow replacing with a newer version of the same transaction
    CTransaction* ptxOld = NULL;
    for (int i = 0; i < vin.size(); i++)
    {
        COutPoint outpoint = vin[i].prevout;
        if (mapNextTx.count(outpoint))
        {
            if (ptxOld == NULL)
            {
                ptxOld = mapNextTx[outpoint].ptx;
                if (!IsUpdate(*ptxOld))
                    return false;
            }
            else if (ptxOld != mapNextTx[outpoint].ptx)
                return false;
        }
    }

    // Check against previous transactions
    map<uint256, CTransaction> mapTestPool;
    int64 nFees = 0;
    if (fCheckInputs)
        if (!TestConnectInputs(txdb, mapTestPool, true, false, nFees))
            return error("AcceptTransaction() : TestConnectInputs failed");

    // Store transaction in memory
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        if (ptxOld)
        {
            printf("mapTransaction.erase(%s) replacing with new version\n", ptxOld->GetHash().ToString().c_str());
            mapTransactions.erase(ptxOld->GetHash());
        }
        //printf("mapTransaction.insert(%s)\n  ", hash.ToString().c_str());
        //print();
        mapTransactions[hash] = *this;
        for (int i = 0; i < vin.size(); i++)
            mapNextTx[vin[i].prevout] = CInPoint(&mapTransactions[hash], i);
    }

    // If updated, erase old tx from wallet
    if (ptxOld)
        CRITICAL_BLOCK(cs_mapWallet)
            mapWallet.erase(ptxOld->GetHash());

    nTransactionsUpdated++;
    return true;
}





int CMerkleTx::IsInMainChain() const
{
    if (hashBlock == 0)
        return 0;

    // Find the block it claims to be in
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain())
        return 0;

    // Get merkle root
    CBlock block;
    if (!block.ReadFromDisk(pindex, false))
        return 0;

    // Make sure the merkle branch connects to this block
    if (CBlock::CheckMerkleBranch(GetHash(), vMerkleBranch, nIndex) != block.hashMerkleRoot)
        return 0;

    return pindexBest->nHeight - pindex->nHeight + 1;
}



bool CMerkleTx::AcceptTransaction(CTxDB& txdb, bool fCheckInputs)
{
    if (fClient)
    {
        if (!IsInMainChain() && !ClientConnectInputs())
            return false;
        return CTransaction::AcceptTransaction(txdb, false);
    }
    else
    {
        return CTransaction::AcceptTransaction(txdb, fCheckInputs);
    }
}



bool CWalletTx::AcceptWalletTransaction(CTxDB& txdb, bool fCheckInputs)
{
    foreach(CMerkleTx& tx, vtxPrev)
    {
        uint256 hash = tx.GetHash();
        if (!mapTransactions.count(hash) && !txdb.ContainsTx(hash))
            tx.AcceptTransaction(txdb, fCheckInputs);
    }
    return AcceptTransaction(txdb, fCheckInputs);
}


void CWalletTx::RelayWalletTransaction(CTxDB& txdb)
{
    foreach(CMerkleTx& tx, vtxPrev)
    {
        uint256 hash = tx.GetHash();
        if (!txdb.ContainsTx(hash))
            RelayMessage(CInv(MSG_TX, hash), (CTransaction)tx);
    }
    uint256 hash = GetHash();
    if (!txdb.ContainsTx(hash))
        RelayMessage(CInv(MSG_TX, hash), (CTransaction)*this);
}










//////////////////////////////////////////////////////////////////////////////
//
// CBlock and CBlockIndex
//

bool CBlock::ReadFromDisk(const CBlockIndex* pblockindex, bool fReadTransactions)
{
    return ReadFromDisk(pblockindex->nFile, pblockindex->nBlockPos, fReadTransactions);
}

int64 GetBlockValue(int64 nFees)
{
    int64 nSubsidy = 10000 * CENT;
    for (int i = 100000; i <= nBestHeight; i += 100000)
        nSubsidy /= 2;
    return nSubsidy + nFees;
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast)
{
    const unsigned int nTargetTimespan = 30 * 24 * 60 * 60;
    const unsigned int nTargetSpacing = 15 * 60;
    const unsigned int nIntervals = nTargetTimespan / nTargetSpacing;

    // Cache
    static const CBlockIndex* pindexLastCache;
    static unsigned int nBitsCache;
    static CCriticalSection cs_cache;
    CRITICAL_BLOCK(cs_cache)
        if (pindexLast && pindexLast == pindexLastCache)
            return nBitsCache;

    // Go back 30 days
    const CBlockIndex* pindexFirst = pindexLast;
    for (int i = 0; pindexFirst && i < nIntervals; i++)
        pindexFirst = pindexFirst->pprev;
    if (pindexFirst == NULL)
        return MINPROOFOFWORK;

    // Load first and last block
    CBlock blockFirst;
    if (!blockFirst.ReadFromDisk(pindexFirst, false))
        throw runtime_error("GetNextWorkRequired() : blockFirst.ReadFromDisk failed\n");
    CBlock blockLast;
    if (!blockLast.ReadFromDisk(pindexLast, false))
        throw runtime_error("GetNextWorkRequired() : blockLast.ReadFromDisk failed\n");

    // Limit one change per timespan
    unsigned int nBits = blockLast.nBits;
    if (blockFirst.nBits == blockLast.nBits)
    {
        unsigned int nTimespan = blockLast.nTime - blockFirst.nTime;
        if (nTimespan > nTargetTimespan * 2 && nBits >= MINPROOFOFWORK)
            nBits--;
        else if (nTimespan < nTargetTimespan / 2)
            nBits++;
    }

    CRITICAL_BLOCK(cs_cache)
    {
        pindexLastCache = pindexLast;
        nBitsCache = nBits;
    }
    return nBits;
}

uint256 GetOrphanRoot(const CBlock* pblock)
{
    // Work back to the first block in the orphan chain
    while (mapOrphanBlocks.count(pblock->hashPrevBlock))
        pblock = mapOrphanBlocks[pblock->hashPrevBlock];
    return pblock->hashPrevBlock;
}









bool CBlock::TestDisconnectBlock(CTxDB& txdb, map<uint256, CTransaction>& mapTestPool)
{
    foreach(CTransaction& tx, vtx)
        if (!tx.TestDisconnectInputs(txdb, mapTestPool))
            return false;
    return true;
}

bool CBlock::TestConnectBlock(CTxDB& txdb, map<uint256, CTransaction>& mapTestPool)
{
    int64 nFees = 0;
    foreach(CTransaction& tx, vtx)
        if (!tx.TestConnectInputs(txdb, mapTestPool, false, false, nFees))
            return false;

    if (vtx[0].GetValueOut() != GetBlockValue(nFees))
        return false;
    return true;
}

bool CBlock::DisconnectBlock()
{
    CTxDB txdb;
    foreach(CTransaction& tx, vtx)
        if (!tx.DisconnectInputs(txdb))
            return false;
    return true;
}

bool CBlock::ConnectBlock(unsigned int nFile, unsigned int nBlockPos, int nHeight)
{
    //// issue here: it doesn't know the version
    unsigned int nTxPos = nBlockPos + ::GetSerializeSize(CBlock(), SER_DISK) - 1 + GetSizeOfCompactSize(vtx.size());

    CTxDB txdb;
    foreach(CTransaction& tx, vtx)
    {
        CDiskTxPos posThisTx(nFile, nBlockPos, nTxPos);
        nTxPos += ::GetSerializeSize(tx, SER_DISK);

        if (!tx.ConnectInputs(txdb, posThisTx, nHeight))
            return false;
    }
    txdb.Close();

    // Watch for transactions paying to me
    foreach(CTransaction& tx, vtx)
        AddToWalletIfMine(tx, this);

    return true;
}



bool Reorganize(CBlockIndex* pindexNew, bool fWriteDisk)
{
    // Find the fork
    CBlockIndex* pfork = pindexBest;
    CBlockIndex* plonger = pindexNew;
    while (pfork != plonger)
    {
        if (!(pfork = pfork->pprev))
            return false;
        while (plonger->nHeight > pfork->nHeight)
            if (!(plonger = plonger->pprev))
                return false;
    }

    // List of what to disconnect
    vector<CBlockIndex*> vDisconnect;
    for (CBlockIndex* pindex = pindexBest; pindex != pfork; pindex = pindex->pprev)
        vDisconnect.push_back(pindex);

    // List of what to connect
    vector<CBlockIndex*> vConnect;
    for (CBlockIndex* pindex = pindexNew; pindex != pfork; pindex = pindex->pprev)
        vConnect.push_back(pindex);
    reverse(vConnect.begin(), vConnect.end());

    // Pretest the reorg
    if (fWriteDisk)
    {
        CTxDB txdb("r");
        map<uint256, CTransaction> mapTestPool;

        foreach(CBlockIndex* pindex, vDisconnect)
            if (!pindex->TestDisconnectBlock(txdb, mapTestPool))
                return false;

        bool fValid = true;
        foreach(CBlockIndex* pindex, vConnect)
        {
            fValid = fValid && pindex->TestConnectBlock(txdb, mapTestPool);
            if (!fValid)
            {
                // Invalid block, delete the rest of this branch
                CBlock block;
                block.ReadFromDisk(pindex, false);
                pindex->EraseBlockFromDisk();
                mapBlockIndex.erase(block.GetHash());
                delete pindex;
            }
        }
        if (!fValid)
            return false;
    }

    // Disconnect shorter branch
    foreach(CBlockIndex* pindex, vDisconnect)
    {
        if (fWriteDisk && !pindex->DisconnectBlock())
            return false;
        if (pindex->pprev)
            pindex->pprev->pnext = NULL;
    }

    // Connect longer branch
    foreach(CBlockIndex* pindex, vConnect)
    {
        if (fWriteDisk && !pindex->ConnectBlock())
            return false;
        if (pindex->pprev)
            pindex->pprev->pnext = pindex;
    }

    return true;
}


bool CBlock::AddToBlockIndex(unsigned int nFile, unsigned int nBlockPos, bool fWriteDisk)
{
    uint256 hash = GetHash();

    // Add to block index
    CBlockIndex* pindexNew = new CBlockIndex(nFile, nBlockPos);
    if (!pindexNew)
        return false;
    mapBlockIndex[hash] = pindexNew;
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashPrevBlock);
    if (mi != mapBlockIndex.end())
    {
        pindexNew->pprev = (*mi).second;
        pindexNew->nHeight = pindexNew->pprev->nHeight + 1;
    }

    // New best
    if (pindexNew->nHeight > nBestHeight)
    {
        if (pindexGenesisBlock == NULL && hash == hashGenesisBlock)
        {
            pindexGenesisBlock = pindexNew;
        }
        else if (hashPrevBlock == hashTimeChainBest)
        {
            // Adding to current best branch
            if (fWriteDisk)
                if (!pindexNew->ConnectBlock())
                    return false;
            pindexNew->pprev->pnext = pindexNew;
        }
        else
        {
            // New best branch
            if (!Reorganize(pindexNew, fWriteDisk))
                return false;
        }

        // New best link
        nBestHeight = pindexNew->nHeight;
        hashTimeChainBest = hash;
        pindexBest = pindexNew;
        nTransactionsUpdated++;

        // Relay wallet transactions that haven't gotten in yet
        if (fWriteDisk && nTime > GetAdjustedTime() - 30 * 60)
            RelayWalletTransactions();
    }

    MainFrameRepaint();
    return true;
}





template<typename Stream>
bool ScanMessageStart(Stream& s)
{
    // Scan ahead to the next pchMessageStart, which should normally be immediately
    // at the file pointer.  Leaves file pointer at end of pchMessageStart.
    s.clear(0);
    short prevmask = s.exceptions(0);
    const char* p = BEGIN(pchMessageStart);
    try
    {
        loop
        {
            char c;
            s.read(&c, 1);
            if (s.fail())
            {
                s.clear(0);
                s.exceptions(prevmask);
                return false;
            }
            if (*p != c)
                p = BEGIN(pchMessageStart);
            if (*p == c)
            {
                if (++p == END(pchMessageStart))
                {
                    s.clear(0);
                    s.exceptions(prevmask);
                    return true;
                }
            }
        }
    }
    catch (...)
    {
        s.clear(0);
        s.exceptions(prevmask);
        return false;
    }
}

FILE* OpenBlockFile(unsigned int nFile, unsigned int nBlockPos, const char* pszMode)
{
    if (nFile == -1)
        return NULL;
    FILE* file = fopen(strprintf("blk%04d.dat", nFile).c_str(), pszMode);
    if (!file)
        return NULL;
    if (nBlockPos != 0 && !strchr(pszMode, 'a') && !strchr(pszMode, 'w'))
    {
        if (fseek(file, nBlockPos, SEEK_SET) != 0)
        {
            fclose(file);
            return NULL;
        }
    }
    return file;
}

static unsigned int nCurrentBlockFile = 1;

FILE* AppendBlockFile(unsigned int& nFileRet)
{
    nFileRet = 0;
    loop
    {
        FILE* file = OpenBlockFile(nCurrentBlockFile, 0, "ab");
        if (!file)
            return NULL;
        if (fseek(file, 0, SEEK_END) != 0)
            return NULL;
        // FAT32 filesize max 4GB, fseek and ftell max 2GB, so we must stay under 2GB
        if (ftell(file) < 0x7F000000 - MAX_SIZE)
        {
            nFileRet = nCurrentBlockFile;
            return file;
        }
        fclose(file);
        nCurrentBlockFile++;
    }
}

bool LoadBlockIndex(bool fAllowNew)
{
    //
    // Load from disk
    //
    for (nCurrentBlockFile = 1;; nCurrentBlockFile++)
    {
        CAutoFile filein = OpenBlockFile(nCurrentBlockFile, 0, "rb");
        if (filein == NULL)
        {
            if (nCurrentBlockFile > 1)
            {
                nCurrentBlockFile--;
                break;
            }
            if (!fAllowNew)
                return false;

            //// debug
            // Genesis Block:
            // GetHash()      = 0x000006b15d1327d67e971d1de9116bd60a3a01556c91b6ebaa416ebc0cfaa646
            // hashPrevBlock  = 0x0000000000000000000000000000000000000000000000000000000000000000
            // hashMerkleRoot = 0x769a5e93fac273fd825da42d39ead975b5d712b2d50953f35a4fdebdec8083e3
            // txNew.vin[0].scriptSig      = 247422313
            // txNew.vout[0].nValue        = 10000
            // txNew.vout[0].scriptPubKey  = OP_CODESEPARATOR 0x31D18A083F381B4BDE37B649AACF8CD0AFD88C53A3587ECDB7FAF23D449C800AF1CE516199390BFE42991F10E7F5340F2A63449F0B639A7115C667E5D7B051D404 OP_CHECKSIG
            // nTime          = 1221069728
            // nBits          = 20
            // nNonce         = 141755
            // CBlock(hashPrevBlock=000000, hashMerkleRoot=769a5e, nTime=1221069728, nBits=20, nNonce=141755, vtx=1)
            //   CTransaction(vin.size=1, vout.size=1, nLockTime=0)
            //     CTxIn(COutPoint(000000, -1), coinbase 04695dbf0e)
            //     CTxOut(nValue=10000, nSequence=4294967295, scriptPubKey=51b0, posNext=null)
            //   vMerkleTree: 769a5e

            // Genesis block
            CTransaction txNew;
            txNew.vin.resize(1);
            txNew.vout.resize(1);
            txNew.vin[0].scriptSig     = CScript() << 247422313;
            txNew.vout[0].nValue       = 10000;
            txNew.vout[0].scriptPubKey = CScript() << OP_CODESEPARATOR << CBigNum("0x31D18A083F381B4BDE37B649AACF8CD0AFD88C53A3587ECDB7FAF23D449C800AF1CE516199390BFE42991F10E7F5340F2A63449F0B639A7115C667E5D7B051D404") << OP_CHECKSIG;
            CBlock block;
            block.vtx.push_back(txNew);
            block.hashPrevBlock = 0;
            block.hashMerkleRoot = block.BuildMerkleTree();
            block.nTime  = 1221069728;
            block.nBits  = 20;
            block.nNonce = 141755;

                //// debug print
                printf("%s\n", block.GetHash().ToString().c_str());
                printf("%s\n", block.hashMerkleRoot.ToString().c_str());
                printf("%s\n", hashGenesisBlock.ToString().c_str());
                txNew.vout[0].scriptPubKey.print();
                block.print();
                assert(block.hashMerkleRoot == uint256("0x769a5e93fac273fd825da42d39ead975b5d712b2d50953f35a4fdebdec8083e3"));

            assert(block.GetHash() == hashGenesisBlock);

            // Start new block file
            unsigned int nFile;
            unsigned int nBlockPos;
            if (!block.WriteToDisk(true, nFile, nBlockPos))
                return false;
            if (!block.AddToBlockIndex(nFile, nBlockPos, true))
                return false;
            break;
        }

        int nFilesize = GetFilesize(filein);
        if (nFilesize == -1)
            return false;
        filein.nType |= SER_BLOCKHEADERONLY;

        while (ScanMessageStart(filein))
        {
            // Read index header
            unsigned int nSize;
            filein >> nSize;
            if (nSize > MAX_SIZE || ftell(filein) + nSize > nFilesize)
                continue;

            // Read block header
            int nBlockPos = ftell(filein);
            CBlock block;
            filein >> block;

            // Skip transactions
            if (fseek(filein, nBlockPos + nSize, SEEK_SET) != 0)
                break; //// is this all we want to do if there's a file error like this?

            // Add to block index without updating disk
            if (!block.AddToBlockIndex(nCurrentBlockFile, nBlockPos, false))
                return false;
        }
    }
    return true;
}



void PrintTimechain()
{
    // precompute tree structure
    map<CBlockIndex*, vector<CBlockIndex*> > mapNext;
    for (map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.begin(); mi != mapBlockIndex.end(); ++mi)
    {
        CBlockIndex* pindex = (*mi).second;
        mapNext[pindex->pprev].push_back(pindex);
        // test
        //while (rand() % 3 == 0)
        //    mapNext[pindex->pprev].push_back(pindex);
    }

    vector<pair<int, CBlockIndex*> > vStack;
    vStack.push_back(make_pair(0, pindexGenesisBlock));

    int nPrevCol = 0;
    while (!vStack.empty())
    {
        int nCol = vStack.back().first;
        CBlockIndex* pindex = vStack.back().second;
        vStack.pop_back();

        // print split or gap
        if (nCol > nPrevCol)
        {
            for (int i = 0; i < nCol-1; i++)
                printf("| ");
            printf("|\\\n");
        }
        else if (nCol < nPrevCol)
        {
            for (int i = 0; i < nCol; i++)
                printf("| ");
            printf("|\n");
        }
        nPrevCol = nCol;

        // print columns
        for (int i = 0; i < nCol; i++)
            printf("| ");

        // print item
        printf("%d (%u,%u)\n", pindex->nHeight, pindex->nFile, pindex->nBlockPos);

        // put the main timechain first
        vector<CBlockIndex*>& vNext = mapNext[pindex];
        for (int i = 0; i < vNext.size(); i++)
        {
            if (vNext[i]->pnext)
            {
                swap(vNext[0], vNext[i]);
                break;
            }
        }

        // iterate children
        for (int i = 0; i < vNext.size(); i++)
            vStack.push_back(make_pair(nCol+i, vNext[i]));
    }
}






bool CBlock::CheckBlock() const
{
    // Size limits
    if (vtx.empty() || vtx.size() > MAX_SIZE || ::GetSerializeSize(*this, SER_DISK) > MAX_SIZE)
        return error("CheckBlock() : size limits failed");

    // Check timestamp
    if (nTime > GetAdjustedTime() + 36 * 60 * 60)
        return error("CheckBlock() : block timestamp out of range");

    // Check proof of work matches claimed amount
    if (nBits < MINPROOFOFWORK)
        return error("CheckBlock() : nBits below minimum");
    if (GetHash() > (~uint256(0) >> nBits))
        return error("CheckBlock() : hash doesn't match nBits");

    // First transaction must be coinbase, the rest must not be
    if (vtx.empty() || !vtx[0].IsCoinBase())
        return error("CheckBlock() : first tx is not coinbase");
    for (int i = 1; i < vtx.size(); i++)
        if (vtx[i].IsCoinBase())
            return error("CheckBlock() : more than one coinbase");

    // Check transactions
    foreach(const CTransaction& tx, vtx)
        if (!tx.CheckTransaction())
            return error("CheckBlock() : CheckTransaction failed");

    // Check merkleroot
    if (hashMerkleRoot != BuildMerkleTree())
        return error("CheckBlock() : hashMerkleRoot mismatch");

    return true;
}

bool CBlock::AcceptBlock()
{
    // Check for duplicate
    uint256 hash = GetHash();
    if (mapBlockIndex.count(hash))
        return false;

    // Get prev block index
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashPrevBlock);
    if (mi == mapBlockIndex.end())
        return false;
    CBlockIndex* pindexPrev = (*mi).second;

    // Check timestamp against prev
    CBlock blockPrev;
    if (!blockPrev.ReadFromDisk(pindexPrev, false))
        return false;
    if (nTime <= blockPrev.nTime)
        return false;

    // Check proof of work
    if (nBits != GetNextWorkRequired(pindexPrev))
        return false;

    // Check transaction inputs and verify signatures
    {
        CTxDB txdb("r");
        map<uint256, CTransaction> mapTestPool;
        bool fIgnoreDiskConflicts = (hashPrevBlock != hashTimeChainBest);
        int64 nFees = 0;
        foreach(CTransaction& tx, vtx)
            if (!tx.TestConnectInputs(txdb, mapTestPool, false, fIgnoreDiskConflicts, nFees))
                return error("AcceptBlock() : TestConnectInputs failed");
        if (vtx[0].GetValueOut() != GetBlockValue(nFees))
            return false;
    }

    // Write block to history file
    unsigned int nFile;
    unsigned int nBlockPos;
    if (!WriteToDisk(!fClient, nFile, nBlockPos))
        return false;
    if (!AddToBlockIndex(nFile, nBlockPos, true))
        return false;

    if (hashTimeChainBest == hash)
        RelayInventory(CInv(MSG_BLOCK, hash));

    // Add atoms to user reviews for coins created
    vector<unsigned char> vchPubKey;
    if (ExtractPubKey(vtx[0].vout[0].scriptPubKey, false, vchPubKey))
    {
        uint64 nRand = 0;
        RAND_bytes((unsigned char*)&nRand, sizeof(nRand));
        unsigned short nAtom = nRand % (USHRT_MAX - 100) + 100;
        vector<unsigned short> vAtoms(1, nAtom);
        AddAtomsAndPropagate(Hash(vchPubKey.begin(), vchPubKey.end()), vAtoms, true);
    }

    return true;
}

bool ProcessBlock(CNode* pfrom, CBlock* pblock)
{
    // Check for duplicate
    uint256 hash = pblock->GetHash();
    if (mapBlockIndex.count(hash) || mapOrphanBlocks.count(hash))
        return false;

    // Preliminary checks
    if (!pblock->CheckBlock())
    {
        printf("CheckBlock FAILED\n");
        delete pblock;
        return false;
    }

    // If don't already have its previous block, shunt it off to holding area until we get it
    if (!mapBlockIndex.count(pblock->hashPrevBlock))
    {
        mapOrphanBlocks.insert(make_pair(hash, pblock));
        mapOrphanBlocksByPrev.insert(make_pair(pblock->hashPrevBlock, pblock));

        // Ask this guy to fill in what we're missing
        if (pfrom)
            pfrom->PushMessage("getblocks", CBlockLocator(pindexBest), GetOrphanRoot(pblock));
        return true;
    }

    // Store to disk
    if (!pblock->AcceptBlock())
    {
        printf("AcceptBlock FAILED\n");
        delete pblock;
        return false;
    }
    delete pblock;

    // Now process any orphan blocks that depended on this one
    for (multimap<uint256, CBlock*>::iterator mi = mapOrphanBlocksByPrev.lower_bound(hash);
         mi != mapOrphanBlocksByPrev.upper_bound(hash);
         ++mi)
    {
        CBlock* pblockOrphan = (*mi).second;
        pblockOrphan->AcceptBlock();
        mapOrphanBlocks.erase(pblockOrphan->GetHash());
        delete pblockOrphan;
    }
    mapOrphanBlocksByPrev.erase(hash);

    return true;
}














//////////////////////////////////////////////////////////////////////////////
//
// Messages
//


bool AlreadyHave(const CInv& inv)
{
    switch (inv.type)
    {
    case MSG_TX:        return mapTransactions.count(inv.hash);
    case MSG_BLOCK:     return mapBlockIndex.count(inv.hash) || mapOrphanBlocks.count(inv.hash);
    case MSG_REVIEW:    return true;
    case MSG_PRODUCT:   return mapProducts.count(inv.hash);
    case MSG_TABLE:     return mapTables.count(inv.hash);
    }
    // Don't know what it is, just say we already got one
    return true;
}







bool ProcessMessages(CNode* pfrom)
{
    CDataStream& vRecv = pfrom->vRecv;
    if (vRecv.empty())
        return true;
    printf("ProcessMessages(%d bytes)\n", vRecv.size());

    //
    // Message format
    //  (4) message start
    //  (12) command
    //  (4) size
    //  (x) data
    //

    loop
    {
        // Scan for message start
        CDataStream::iterator pstart = search(vRecv.begin(), vRecv.end(), BEGIN(pchMessageStart), END(pchMessageStart));
        if (vRecv.end() - pstart < sizeof(CMessageHeader))
        {
            if (vRecv.size() > sizeof(CMessageHeader))
            {
                printf("\n\nPROCESSMESSAGE MESSAGESTART NOT FOUND\n\n");
                vRecv.erase(vRecv.begin(), vRecv.end() - sizeof(CMessageHeader));
            }
            break;
        }
        if (pstart - vRecv.begin() > 0)
            printf("\n\nPROCESSMESSAGE SKIPPED %d BYTES\n\n", pstart - vRecv.begin());
        vRecv.erase(vRecv.begin(), pstart);

        // Read header
        CMessageHeader hdr;
        vRecv >> hdr;
        if (!hdr.IsValid())
        {
            printf("\n\nPROCESSMESSAGE: ERRORS IN HEADER %s\n\n\n", hdr.GetCommand().c_str());
            continue;
        }
        string strCommand = hdr.GetCommand();

        // Message size
        unsigned int nMessageSize = hdr.nMessageSize;
        if (nMessageSize > vRecv.size())
        {
            // Rewind and wait for rest of message
            ///// need a mechanism to give up waiting for overlong message size error
            printf("MESSAGE-BREAK 2\n");
            vRecv.insert(vRecv.begin(), BEGIN(hdr), END(hdr));
            break;
        }

        // Copy message to its own buffer
        CDataStream vMsg(vRecv.begin(), vRecv.begin() + nMessageSize, vRecv.nType, vRecv.nVersion);
        vRecv.ignore(nMessageSize);

        // Process message
        bool fRet = false;
        try
        {
            fRet = ProcessMessage(pfrom, strCommand, vMsg);
        }
        CATCH_PRINT_EXCEPTION("ProcessMessage()")
        if (!fRet)
            printf("ProcessMessage(%s, %d bytes) from %s to %s FAILED\n", strCommand.c_str(), nMessageSize, pfrom->addr.ToString().c_str(), addrLocalHost.ToString().c_str());
    }

    vRecv.Compact();
    return true;
}




bool ProcessMessage(CNode* pfrom, string strCommand, CDataStream& vRecv)
{
    static map<unsigned int, vector<unsigned char> > mapReuseKey;
    CheckForShutdown(2);
    printf("received: %-12s (%d bytes)  ", strCommand.c_str(), vRecv.size());
    for (int i = 0; i < min(vRecv.size(), (unsigned int)25); i++)
        printf("%02x ", vRecv[i] & 0xff);
    printf("\n");


    if (strCommand == "version")
    {
        // Can only do this once
        if (pfrom->nVersion != 0)
            return false;

        unsigned int nTime;
        vRecv >> pfrom->nVersion >> pfrom->nServices >> nTime;
        if (pfrom->nVersion == 0)
            return false;

        pfrom->vSend.SetVersion(min(pfrom->nVersion, VERSION));
        pfrom->vRecv.SetVersion(min(pfrom->nVersion, VERSION));

        pfrom->fClient = !(pfrom->nServices & NODE_NETWORK);
        if (pfrom->fClient)
        {
            pfrom->vSend.nType |= SER_BLOCKHEADERONLY;
            pfrom->vRecv.nType |= SER_BLOCKHEADERONLY;
        }

        AddTimeData(pfrom->addr.ip, nTime);

        // Ask the first connected node for block updates
        static bool fAskedForBlocks;
        if (!fAskedForBlocks && !pfrom->fClient)
        {
            fAskedForBlocks = true;
            pfrom->PushMessage("getblocks", CBlockLocator(pindexBest), uint256(0));
        }
    }


    else if (pfrom->nVersion == 0)
    {
        // Must have a version message before anything else
        return false;
    }


    else if (strCommand == "addr")
    {
        vector<CAddress> vAddr;
        vRecv >> vAddr;

        // Store the new addresses
        CAddrDB addrdb;
        foreach(const CAddress& addr, vAddr)
        {
            if (AddAddress(addrdb, addr))
            {
                // Put on lists to send to other nodes
                pfrom->setAddrKnown.insert(addr);
                CRITICAL_BLOCK(cs_vNodes)
                    foreach(CNode* pnode, vNodes)
                        if (!pnode->setAddrKnown.count(addr))
                            pnode->vAddrToSend.push_back(addr);
            }
        }
    }


    else if (strCommand == "inv")
    {
        vector<CInv> vInv;
        vRecv >> vInv;

        foreach(const CInv& inv, vInv)
        {
            printf("  got inventory: %s  %s\n", inv.ToString().c_str(), AlreadyHave(inv) ? "have" : "new");

            CRITICAL_BLOCK(pfrom->cs_inventory)
                pfrom->setInventoryKnown.insert(inv);

            if (!AlreadyHave(inv))
                pfrom->AskFor(inv);
            else if (inv.type == MSG_BLOCK && mapOrphanBlocks.count(inv.hash))
                pfrom->PushMessage("getblocks", CBlockLocator(pindexBest), GetOrphanRoot(mapOrphanBlocks[inv.hash]));
        }
    }


    else if (strCommand == "getdata")
    {
        vector<CInv> vInv;
        vRecv >> vInv;

        foreach(const CInv& inv, vInv)
        {
            printf("received getdata for: %s\n", inv.ToString().c_str());

            if (inv.type == MSG_BLOCK)
            {
                // Send block from disk
                map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(inv.hash);
                if (mi != mapBlockIndex.end())
                {
                    CBlock block;
                    block.ReadFromDisk((*mi).second, !pfrom->fClient);
                    pfrom->PushMessage("block", block);
                }
            }
            else if (inv.IsKnownType())
            {
                // Send stream from relay memory
                CRITICAL_BLOCK(cs_mapRelay)
                {
                    map<CInv, CDataStream>::iterator mi = mapRelay.find(inv);
                    if (mi != mapRelay.end())
                        pfrom->PushMessage(inv.GetCommand(), (*mi).second);
                }
            }
        }
    }


    else if (strCommand == "getblocks")
    {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        // Find the first block the caller has in the main chain
        CBlockIndex* pindex = locator.GetBlockIndex();

        // Send the rest of the chain
        if (pindex)
            pindex = pindex->pnext;
        for (; pindex; pindex = pindex->pnext)
        {
            CBlock block;
            block.ReadFromDisk(pindex, !pfrom->fClient);
            if (block.GetHash() == hashStop)
                break;
            pfrom->PushMessage("block", block);
        }
    }


    else if (strCommand == "getmywtxes")
    {
        CBlockLocator locator;
        vector<uint160> vPubKeyHashes;
        vRecv >> locator >> vPubKeyHashes;

        // Find the owner's new transactions
        int nHeight = locator.GetHeight();
        CTxDB txdb("r");
        foreach(uint160 hash160, vPubKeyHashes)
        {
            vector<CTransaction> vtx;
            if (txdb.ReadOwnerTxes(hash160, nHeight, vtx))
            {
                foreach(const CTransaction& tx, vtx)
                {
                    // Upgrade transaction to a fully supported CWalletTx
                    CWalletTx wtx(tx);
                    wtx.AddSupportingTransactions(txdb);

                    pfrom->PushMessage("wtx", wtx);
                }
            }
        }
    }


    else if (strCommand == "wtx")
    {
        CWalletTx wtx;
        vRecv >> wtx;

        if (!wtx.AcceptWalletTransaction())
            return error("message wtx : AcceptWalletTransaction failed!");
        AddToWallet(wtx);
    }


    else if (strCommand == "tx")
    {
        CDataStream vMsg(vRecv);
        CTransaction tx;
        vRecv >> tx;

        CInv inv(MSG_TX, tx.GetHash());
        pfrom->AddInventoryKnown(inv);

        if (tx.AcceptTransaction())
        {
            AddToWalletIfMine(tx, NULL);
            RelayMessage(inv, vMsg);
            mapAlreadyAskedFor.erase(inv);
        }
    }


    else if (strCommand == "block")
    {
        auto_ptr<CBlock> pblock(new CBlock);
        vRecv >> *pblock;

        //// debug print
        printf("received block:\n"); pblock->print();

        CInv inv(MSG_BLOCK, pblock->GetHash());
        pfrom->AddInventoryKnown(inv);

        if (ProcessBlock(pfrom, pblock.release()))
            mapAlreadyAskedFor.erase(inv);
    }


    else if (strCommand == "getaddr")
    {
        pfrom->vAddrToSend.clear();
        //// need to expand the time range if not enough found
        int64 nSince = GetAdjustedTime() - 60 * 60; // in the last hour
        CRITICAL_BLOCK(cs_mapAddresses)
        {
            foreach(const PAIRTYPE(vector<unsigned char>, CAddress)& item, mapAddresses)
            {
                const CAddress& addr = item.second;
                if (addr.nTime > nSince)
                    pfrom->vAddrToSend.push_back(addr);
            }
        }
    }


    else if (strCommand == "checkorder")
    {
        uint256 hashReply;
        CWalletTx order;
        vRecv >> hashReply >> order;

        /// we have a chance to check the order here

        // Keep giving the same key to the same ip until they use it
        if (!mapReuseKey.count(pfrom->addr.ip))
            mapReuseKey[pfrom->addr.ip] = GenerateNewKey();

        // Send back approval of order and pubkey to use
        CScript scriptPubKey;
        scriptPubKey << OP_CODESEPARATOR << mapReuseKey[pfrom->addr.ip] << OP_CHECKSIG;
        pfrom->PushMessage("reply", hashReply, (int)0, scriptPubKey);
    }


    else if (strCommand == "submitorder")
    {
        uint256 hashReply;
        CWalletTx wtxNew;
        vRecv >> hashReply >> wtxNew;

        // Broadcast
        if (!wtxNew.AcceptWalletTransaction())
        {
            pfrom->PushMessage("reply", hashReply, (int)1);
            return error("submitorder AcceptWalletTransaction() failed, returning error 1");
        }
        AddToWallet(wtxNew);
        wtxNew.RelayWalletTransaction();
        mapReuseKey.erase(pfrom->addr.ip);

        // Send back confirmation
        pfrom->PushMessage("reply", hashReply, (int)0);
    }


    else if (strCommand == "reply")
    {
        uint256 hashReply;
        vRecv >> hashReply;

        CRequestTracker tracker;
        CRITICAL_BLOCK(pfrom->cs_mapRequests)
        {
            map<uint256, CRequestTracker>::iterator mi = pfrom->mapRequests.find(hashReply);
            if (mi != pfrom->mapRequests.end())
            {
                tracker = (*mi).second;
                pfrom->mapRequests.erase(mi);
            }
        }
        if (!tracker.IsNull())
            tracker.fn(tracker.param1, vRecv);
    }


    else
    {
        // Ignore unknown commands for extensibility
        printf("ProcessMessage(%s) : Ignored unknown message\n", strCommand.c_str());
    }


    if (!vRecv.empty())
        printf("ProcessMessage(%s) : %d extra bytes\n", strCommand.c_str(), vRecv.size());

    return true;
}









bool SendMessages(CNode* pto)
{
    CheckForShutdown(2);

    // Don't send anything until we get their version message
    if (pto->nVersion == 0)
        return true;


    //
    // Message: addr
    //
    vector<CAddress> vAddrToSend;
    vAddrToSend.reserve(pto->vAddrToSend.size());
    foreach(const CAddress& addr, pto->vAddrToSend)
        if (!pto->setAddrKnown.count(addr))
            vAddrToSend.push_back(addr);
    pto->vAddrToSend.clear();
    if (!vAddrToSend.empty())
        pto->PushMessage("addr", vAddrToSend);


    //
    // Message: inventory
    //
    vector<CInv> vInventoryToSend;
    CRITICAL_BLOCK(pto->cs_inventory)
    {
        vInventoryToSend.reserve(pto->vInventoryToSend.size());
        foreach(const CInv& inv, pto->vInventoryToSend)
            if (!pto->setInventoryKnown.count(inv))
                vInventoryToSend.push_back(inv);
        pto->vInventoryToSend.clear();
    }
    if (!vInventoryToSend.empty())
        pto->PushMessage("inv", vInventoryToSend);


    //
    // Message: getdata
    //
    vector<CInv> vAskFor;
    int64 nNow = GetTime();
    while (!pto->mapAskFor.empty() && (*pto->mapAskFor.begin()).first <= nNow)
    {
        const CInv& inv = (*pto->mapAskFor.begin()).second;
        printf("getdata %s\n", inv.ToString().c_str());
        if (!AlreadyHave(inv))
            vAskFor.push_back(inv);
        pto->mapAskFor.erase(pto->mapAskFor.begin());
    }
    if (!vAskFor.empty())
        pto->PushMessage("getdata", vAskFor);



    return true;
}














//////////////////////////////////////////////////////////////////////////////
//
// BitcoinMiner
//

int FormatHashBlocks(void* pbuffer, unsigned int len)
{
    unsigned char* pdata = (unsigned char*)pbuffer;
    unsigned int blocks = 1 + ((len + 8) / 64);
    unsigned char* pend = pdata + 64 * blocks;
    memset(pdata + len, 0, 64 * blocks - len);
    pdata[len] = 0x80;
    unsigned int bits = len * 8;
    pend[-1] = (bits >> 0) & 0xff;
    pend[-2] = (bits >> 8) & 0xff;
    pend[-3] = (bits >> 16) & 0xff;
    pend[-4] = (bits >> 24) & 0xff;
    return blocks;
}

using CryptoPP::ByteReverse;
static int detectlittleendian = 1;

void BlockSHA256(const void* pin, unsigned int nBlocks, void* pout)
{
    unsigned int* pinput = (unsigned int*)pin;
    unsigned int* pstate = (unsigned int*)pout;

    CryptoPP::SHA256::InitState(pstate);

    if (*(char*)&detectlittleendian != 0)
    {
        for (int n = 0; n < nBlocks; n++)
        {
            unsigned int pbuf[16];
            for (int i = 0; i < 16; i++)
                pbuf[i] = ByteReverse(pinput[n * 16 + i]);
            CryptoPP::SHA256::Transform(pstate, pbuf);
        }
        for (int i = 0; i < 8; i++)
            pstate[i] = ByteReverse(pstate[i]);
    }
    else
    {
        for (int n = 0; n < nBlocks; n++)
            CryptoPP::SHA256::Transform(pstate, pinput + n * 16);
    }
}


bool BitcoinMiner()
{
    printf("BitcoinMiner started\n");

    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_LOWEST);



    CBlock blockPrev;
    while (fGenerateBitcoins)
    {
        CheckForShutdown(3);

        //
        // Create coinbase tx
        //
        CTransaction txNew;
        txNew.vin.resize(1);
        txNew.vin[0].prevout.SetNull();
        CBigNum bnNonce; // this nonce is so multiple processes working for the same keyUser
        BN_rand_range(&bnNonce, &CBigNum(INT_MAX));  // don't cover the same ground
        txNew.vin[0].scriptSig << bnNonce;
        txNew.vout.resize(1);
        txNew.vout[0].scriptPubKey << OP_CODESEPARATOR << keyUser.GetPubKey() << OP_CHECKSIG;
        txNew.vout[0].posNext.SetNull();


        //
        // Create new block
        //
        auto_ptr<CBlock> pblock(new CBlock());
        if (!pblock.get())
            return false;

        // Add our coinbase tx as first transaction
        pblock->vtx.push_back(txNew);

        // Collect the latest transactions into the block
        unsigned int nTransactionsUpdatedLast = nTransactionsUpdated;
        int64 nFees = 0;
        CRITICAL_BLOCK(cs_mapTransactions)
        {
            CTxDB txdb("r");
            set<uint256> setInThisBlock;
            vector<char> vfAlreadyAdded(mapTransactions.size());
            bool fFoundSomething = true;
            unsigned int nSize = 0;
            while (fFoundSomething && nSize < MAX_SIZE/2)
            {
                fFoundSomething = false;
                unsigned int n = 0;
                for (map<uint256, CTransaction>::iterator mi = mapTransactions.begin(); mi != mapTransactions.end(); ++mi, ++n)
                {
                    if (vfAlreadyAdded[n])
                        continue;
                    CTransaction& tx = (*mi).second;
                    if (!tx.IsFinal() || tx.IsCoinBase())
                        continue;

                    // Find if all dependencies are in this or previous blocks
                    bool fHaveAllPrev = true;
                    int64 nValueIn = 0;
                    foreach(const CTxIn& txin, tx.vin)
                    {
                        COutPoint prevout = txin.prevout;
                        CTransaction txPrev;
                        if (setInThisBlock.count(prevout.hash))
                        {
                            txPrev = mapTransactions[prevout.hash];
                        }
                        else if (!txdb.ReadDiskTx(prevout.hash, txPrev))
                        {
                            fHaveAllPrev = false;
                            break;
                        }
                        if (prevout.n >= txPrev.vout.size())
                        {
                            fHaveAllPrev = false;
                            break;
                        }
                        nValueIn += txPrev.vout[prevout.n].nValue;
                    }
                    int64 nTransactionFee = nValueIn - tx.GetValueOut();
                    if (nTransactionFee < 0) // could require a tx fee here
                        continue;

                    // Add tx to block
                    if (fHaveAllPrev)
                    {
                        fFoundSomething = true;
                        pblock->vtx.push_back(tx);
                        nSize += ::GetSerializeSize(tx, SER_NETWORK);
                        nFees += nTransactionFee;
                        vfAlreadyAdded[n] = true;
                        setInThisBlock.insert(tx.GetHash());
                    }
                }
            }
        }

        // Update last few things
        pblock->vtx[0].vout[0].nValue = GetBlockValue(nFees);
        pblock->hashMerkleRoot = pblock->BuildMerkleTree();


        printf("\n\nRunning BitcoinMiner with %d transactions in block\n", pblock->vtx.size());


        //
        // Prebuild hash buffer
        //
        struct unnamed1
        {
            struct unnamed2
            {
                uint256 hashPrevBlock;
                uint256 hashMerkleRoot;
                unsigned int nTime;
                unsigned int nBits;
                unsigned int nNonce;
            }
            block;
            unsigned char pchPadding0[64];
            uint256 hash1;
            unsigned char pchPadding1[64];
        }
        tmp;

        const CBlockIndex* pindexPrev = pindexBest;
        tmp.block.hashPrevBlock = pblock->hashPrevBlock = hashTimeChainBest;
        tmp.block.hashMerkleRoot = pblock->hashMerkleRoot;

        // Get time of previous block
        if (pindexPrev)
        {
            if (blockPrev.GetHash() != pblock->hashPrevBlock)
                blockPrev.ReadFromDisk(pindexPrev, false);
            if (blockPrev.GetHash() != pblock->hashPrevBlock)
            {
                printf("pindexBest and hashTimeChainBest out of sync\n");
                continue;
            }
        }
        tmp.block.nTime = pblock->nTime = max(blockPrev.nTime+1, (unsigned int)GetAdjustedTime());
        tmp.block.nBits = pblock->nBits = GetNextWorkRequired(pindexPrev);
        tmp.block.nNonce = 1;

        unsigned int nBlocks0 = FormatHashBlocks(&tmp.block, sizeof(tmp.block));
        unsigned int nBlocks1 = FormatHashBlocks(&tmp.hash1, sizeof(tmp.hash1));


        //
        // Search
        //
        uint256 hashTarget = (~uint256(0) >> pblock->nBits);
        uint256 hash;
        while (nTransactionsUpdated == nTransactionsUpdatedLast)
        {
            BlockSHA256(&tmp.block, nBlocks0, &tmp.hash1);
            BlockSHA256(&tmp.hash1, nBlocks1, &hash);

            if (hash <= hashTarget)
            {
                pblock->nNonce = tmp.block.nNonce;
                assert(hash == pblock->GetHash());

                    //// debug print
                    printf("BitcoinMiner:\n");
                    printf("supercoin found  \n  hash: %s  \ntarget: %s\n", hash.GetHex().c_str(), hashTarget.GetHex().c_str());
                    pblock->print();

                // Process this block the same as if we had received it from another node
                if (!ProcessBlock(NULL, pblock.release()))
                    printf("ERROR in BitcoinMiner, ProcessBlock, block not accepted\n");
                break;
            }

            // Update nTime every few seconds
            if ((++tmp.block.nNonce & 0xfffff) == 0)
            {
                if (tmp.block.nNonce == 0)
                    break;
                tmp.block.nTime = pblock->nTime = max(blockPrev.nTime+1, (unsigned int)GetAdjustedTime());
            }
        }
    }

    return true;
}


















//////////////////////////////////////////////////////////////////////////////
//
// Actions
//


int64 CountMoney()
{
    int64 nTotal = 0;
    CRITICAL_BLOCK(cs_mapWallet)
    {
        for (map<uint256, CWalletTx>::iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            CWalletTx* pcoin = &(*it).second;
            if (!pcoin->IsFinal() || pcoin->fSpent)
                continue;
            nTotal += pcoin->GetCredit();
        }
    }
    return nTotal;
}



bool SelectCoins(int64 nTargetValue, set<CWalletTx*>& setCoinsRet)
{
    setCoinsRet.clear();

    // List of values less than target
    int64 nLowestLarger = _I64_MAX;
    CWalletTx* pcoinLowestLarger = NULL;
    vector<pair<int64, CWalletTx*> > vValue;
    int64 nTotalLower = 0;

    CRITICAL_BLOCK(cs_mapWallet)
    {
        for (map<uint256, CWalletTx>::iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            CWalletTx* pcoin = &(*it).second;
            if (!pcoin->IsFinal() || pcoin->fSpent)
                continue;
            int64 n = pcoin->GetCredit();
            if (n < nTargetValue)
            {
                vValue.push_back(make_pair(n, pcoin));
                nTotalLower += n;
            }
            else if (n == nTargetValue)
            {
                setCoinsRet.insert(pcoin);
                return true;
            }
            else if (n < nLowestLarger)
            {
                nLowestLarger = n;
                pcoinLowestLarger = pcoin;
            }
        }
    }

    if (nTotalLower < nTargetValue)
    {
        if (pcoinLowestLarger == NULL)
            return false;
        setCoinsRet.insert(pcoinLowestLarger);
        return true;
    }

    // Solve subset sum by stochastic approximation
    sort(vValue.rbegin(), vValue.rend());
    vector<char> vfIncluded;
    vector<char> vfBest(vValue.size(), true);
    int64 nBest = nTotalLower;

    for (int nRep = 0; nRep < 1000 && nBest != nTargetValue; nRep++)
    {
        vfIncluded.assign(vValue.size(), false);
        int64 nTotal = 0;
        for (int i = 0; i < vValue.size(); i++)
        {
            if (rand() % 2)
            {
                nTotal += vValue[i].first;
                vfIncluded[i] = true;
                if (nTotal >= nTargetValue)
                {
                    if (nTotal < nBest)
                    {
                        nBest = nTotal;
                        vfBest = vfIncluded;
                    }
                    nTotal -= vValue[i].first;
                    vfIncluded[i] = false;
                }
            }
        }
    }

    // If the next larger is still closer, return it
    if (pcoinLowestLarger && nLowestLarger - nTargetValue <= nBest - nTargetValue)
        setCoinsRet.insert(pcoinLowestLarger);
    else
        for (int i = 0; i < vValue.size(); i++)
            if (vfBest[i])
                setCoinsRet.insert(vValue[i].second);
    return true;
}



bool CreateTransaction(CScript scriptPubKey, int64 nValue, CWalletTx& wtxNew)
{
    wtxNew.vin.clear();
    wtxNew.vout.clear();
    if (nValue < TRANSACTIONFEE)
        return false;

    // Choose coins to use
    set<CWalletTx*> setCoins;
    if (!SelectCoins(nValue, setCoins))
        return false;
    int64 nValueIn = 0;
    foreach(CWalletTx* pcoin, setCoins)
        nValueIn += pcoin->GetCredit();

    // Fill vout[0] to the payee
    int64 nValueOut = nValue - TRANSACTIONFEE;
    wtxNew.vout.push_back(CTxOut(nValueOut, scriptPubKey));

    // Fill vout[1] back to self with any change
    if (nValueIn - TRANSACTIONFEE > nValueOut)
    {
        // Use the same key as one of the coins
        vector<unsigned char> vchPubKey;
        CTransaction& txFirst = *(*setCoins.begin());
        foreach(const CTxOut& txout, txFirst.vout)
            if (txout.IsMine())
                if (ExtractPubKey(txout.scriptPubKey, true, vchPubKey))
                    break;
        if (vchPubKey.empty())
            return false;

        // Fill vout[1] to ourself
        CScript scriptPubKey;
        scriptPubKey << OP_CODESEPARATOR << vchPubKey << OP_CHECKSIG;
        wtxNew.vout.push_back(CTxOut(nValueIn - TRANSACTIONFEE - nValueOut, scriptPubKey));
    }

    // Fill vin
    foreach(CWalletTx* pcoin, setCoins)
        for (int nOut = 0; nOut < pcoin->vout.size(); nOut++)
            if (pcoin->vout[nOut].IsMine())
                SignSignature(*pcoin, nOut, wtxNew, -1, "all");

    // Fill vtxPrev by copying from previous transactions vtxPrev
    wtxNew.AddSupportingTransactions();

    // Add tx to wallet, because if it has change it's also ours,
    // otherwise just for transaction history.
    wtxNew.nTime = GetAdjustedTime();
    AddToWallet(wtxNew);

    // Mark old coins as spent
    foreach(CWalletTx* pcoin, setCoins)
    {
        pcoin->fSpent = true;
        pcoin->WriteToDisk();
        vWalletUpdated.push_back(make_pair(pcoin->GetHash(), false));
    }

    return true;
}



bool SendMoney(CScript scriptPubKey, int64 nValue, CWalletTx& wtxNew)
{
    if (!CreateTransaction(scriptPubKey, nValue, wtxNew))
        return false;

    // Broadcast
    if (!wtxNew.AcceptTransaction())
    {
        // This must not fail. The transaction has already been signed and recorded.
        throw runtime_error("SendMoney() : wtxNew.AcceptTransaction() failed\n");
        return false;
    }
    wtxNew.RelayWalletTransaction();

    return true;
}
