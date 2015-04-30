// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Darkcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "alert.h"
#include "checkpoints.h"
#include "db.h"
#include "txdb.h"
#include "net.h"
#include "init.h"
#include "ui_interface.h"
#include "checkqueue.h"
#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/tuple/tuple.hpp>


using namespace std;
using namespace boost;

//
// Global smake -f makefile.unix USE_UPNP=-tate
//

CCriticalSection cs_setpwalletRegistered;
set<CWallet*> setpwalletRegistered;

CCriticalSection cs_main;

CTxMemPool mempool;
unsigned int nTransactionsUpdated = 0;

map<uint256, CBlockIndex*> mapBlockIndex;
uint256 hashGenesisBlock("0x1471f84b77a71ff798a39012823edd7d91b11ad7f2b90263a6bbbbe12c4d03fb");
static CBigNum bnProofOfWorkLimit(~uint256(0) >> 20); // Crypto: starting difficulty is 1 / 2^12
CBlockIndex* pindexGenesisBlock = NULL;
int nBestHeight = -1;
uint256 nBestChainWork = 0;
uint256 nBestInvalidWork = 0;
uint256 hashBestChain = 0;
CBlockIndex* pindexBest = NULL;
set<CBlockIndex*, CBlockIndexWorkComparator> setBlockIndexValid; // may contain all CBlockIndex*'s that have validness >=BLOCK_VALID_TRANSACTIONS, and must contain those who aren't failed
int64 nTimeBestReceived = 0;
int nScriptCheckThreads = 0;
bool fImporting = false;
bool fReindex = false;
bool fBenchmark = false;
bool fTxIndex = false;
unsigned int nCoinCacheSize = 5000;
int64 nChainStartTime = 1389306217; // Line: 2815

/** Fees smaller than this (in satoshi) are considered zero fee (for transaction creation) */
int64 CTransaction::nMinTxFee = 1000000;
/** Fees smaller than this (in satoshi) are considered zero fee (for relaying) */
int64 CTransaction::nMinRelayTxFee = 1000000;

CMedianFilter<int> cPeerBlockCounts(8, 0); // Amount of blocks that other nodes claim to have

map<uint256, CBlock*> mapOrphanBlocks;
multimap<uint256, CBlock*> mapOrphanBlocksByPrev;

map<uint256, CTransaction> mapOrphanTransactions;
map<uint256, set<uint256> > mapOrphanTransactionsByPrev;

// Constant stuff for coinbase transactions we create:
CScript COINBASE_FLAGS;

const string strMessageMagic = "Crypto Signed Message:\n";

double dHashesPerSec = 0.0;
int64 nHPSTimerStart = 0;

// Settings
int64 nTransactionFee = 0;
int64 nMinimumInputValue = DUST_HARD_LIMIT;


//////////////////////////////////////////////////////////////////////////////
//
// dispatching functions
//

// These functions dispatch to one or all registered wallets


void RegisterWallet(CWallet* pwalletIn)
{
    {
        LOCK(cs_setpwalletRegistered);
        setpwalletRegistered.insert(pwalletIn);
    }
}

void UnregisterWallet(CWallet* pwalletIn)
{
    {
        LOCK(cs_setpwalletRegistered);
        setpwalletRegistered.erase(pwalletIn);
    }
}

// get the wallet transaction with the given hash (if it exists)
bool static GetTransaction(const uint256& hashTx, CWalletTx& wtx)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        if (pwallet->GetTransaction(hashTx,wtx))
            return true;
    return false;
}

// erases transaction with the given hash from all wallets
void static EraseFromWallets(uint256 hash)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->EraseFromWallet(hash);
}

// make sure all wallets know about the given transaction, in the given block
void SyncWithWallets(const uint256 &hash, const CTransaction& tx, const CBlock* pblock, bool fUpdate)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->AddToWalletIfInvolvingMe(hash, tx, pblock, fUpdate);
}

// notify wallets about a new best chain
void static SetBestChain(const CBlockLocator& loc)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->SetBestChain(loc);
}

// notify wallets about an updated transaction
void static UpdatedTransaction(const uint256& hashTx)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->UpdatedTransaction(hashTx);
}

// dump all wallets
void static PrintWallets(const CBlock& block)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->PrintWallet(block);
}

// notify wallets about an incoming inventory (for request counts)
void static Inventory(const uint256& hash)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->Inventory(hash);
}

// ask wallets to resend their transactions
void static ResendWalletTransactions()
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->ResendWalletTransactions();
}







//////////////////////////////////////////////////////////////////////////////
//
// CCoinsView implementations
//

bool CCoinsView::GetCoins(const uint256 &txid, CCoins &coins) { return false; }
bool CCoinsView::SetCoins(const uint256 &txid, const CCoins &coins) { return false; }
bool CCoinsView::HaveCoins(const uint256 &txid) { return false; }
CBlockIndex *CCoinsView::GetBestBlock() { return NULL; }
bool CCoinsView::SetBestBlock(CBlockIndex *pindex) { return false; }
bool CCoinsView::BatchWrite(const std::map<uint256, CCoins> &mapCoins, CBlockIndex *pindex) { return false; }
bool CCoinsView::GetStats(CCoinsStats &stats) { return false; }


CCoinsViewBacked::CCoinsViewBacked(CCoinsView &viewIn) : base(&viewIn) { }
bool CCoinsViewBacked::GetCoins(const uint256 &txid, CCoins &coins) { return base->GetCoins(txid, coins); }
bool CCoinsViewBacked::SetCoins(const uint256 &txid, const CCoins &coins) { return base->SetCoins(txid, coins); }
bool CCoinsViewBacked::HaveCoins(const uint256 &txid) { return base->HaveCoins(txid); }
CBlockIndex *CCoinsViewBacked::GetBestBlock() { return base->GetBestBlock(); }
bool CCoinsViewBacked::SetBestBlock(CBlockIndex *pindex) { return base->SetBestBlock(pindex); }
void CCoinsViewBacked::SetBackend(CCoinsView &viewIn) { base = &viewIn; }
bool CCoinsViewBacked::BatchWrite(const std::map<uint256, CCoins> &mapCoins, CBlockIndex *pindex) { return base->BatchWrite(mapCoins, pindex); }
bool CCoinsViewBacked::GetStats(CCoinsStats &stats) { return base->GetStats(stats); }

CCoinsViewCache::CCoinsViewCache(CCoinsView &baseIn, bool fDummy) : CCoinsViewBacked(baseIn), pindexTip(NULL) { }

bool CCoinsViewCache::GetCoins(const uint256 &txid, CCoins &coins) {
    if (cacheCoins.count(txid)) {
        coins = cacheCoins[txid];
        return true;
    }
    if (base->GetCoins(txid, coins)) {
        cacheCoins[txid] = coins;
        return true;
    }
    return false;
}

std::map<uint256,CCoins>::iterator CCoinsViewCache::FetchCoins(const uint256 &txid) {
    std::map<uint256,CCoins>::iterator it = cacheCoins.lower_bound(txid);
    if (it != cacheCoins.end() && it->first == txid)
        return it;
    CCoins tmp;
    if (!base->GetCoins(txid,tmp))
        return cacheCoins.end();
    std::map<uint256,CCoins>::iterator ret = cacheCoins.insert(it, std::make_pair(txid, CCoins()));
    tmp.swap(ret->second);
    return ret;
}

CCoins &CCoinsViewCache::GetCoins(const uint256 &txid) {
    std::map<uint256,CCoins>::iterator it = FetchCoins(txid);
    assert(it != cacheCoins.end());
    return it->second;
}

bool CCoinsViewCache::SetCoins(const uint256 &txid, const CCoins &coins) {
    cacheCoins[txid] = coins;
    return true;
}

bool CCoinsViewCache::HaveCoins(const uint256 &txid) {
    return FetchCoins(txid) != cacheCoins.end();
}

CBlockIndex *CCoinsViewCache::GetBestBlock() {
    if (pindexTip == NULL)
        pindexTip = base->GetBestBlock();
    return pindexTip;
}

bool CCoinsViewCache::SetBestBlock(CBlockIndex *pindex) {
    pindexTip = pindex;
    return true;
}

bool CCoinsViewCache::BatchWrite(const std::map<uint256, CCoins> &mapCoins, CBlockIndex *pindex) {
    for (std::map<uint256, CCoins>::const_iterator it = mapCoins.begin(); it != mapCoins.end(); it++)
        cacheCoins[it->first] = it->second;
    pindexTip = pindex;
    return true;
}

bool CCoinsViewCache::Flush() {
    bool fOk = base->BatchWrite(cacheCoins, pindexTip);
    if (fOk)
        cacheCoins.clear();
    return fOk;
}

unsigned int CCoinsViewCache::GetCacheSize() {
    return cacheCoins.size();
}

/** CCoinsView that brings transactions from a memorypool into view.
    It does not check for spendings by memory pool transactions. */
CCoinsViewMemPool::CCoinsViewMemPool(CCoinsView &baseIn, CTxMemPool &mempoolIn) : CCoinsViewBacked(baseIn), mempool(mempoolIn) { }

bool CCoinsViewMemPool::GetCoins(const uint256 &txid, CCoins &coins) {
    if (base->GetCoins(txid, coins))
        return true;
    if (mempool.exists(txid)) {
        const CTransaction &tx = mempool.lookup(txid);
        coins = CCoins(tx, MEMPOOL_HEIGHT);
        return true;
    }
    return false;
}

bool CCoinsViewMemPool::HaveCoins(const uint256 &txid) {
    return mempool.exists(txid) || base->HaveCoins(txid);
}

CCoinsViewCache *pcoinsTip = NULL;
CBlockTreeDB *pblocktree = NULL;

//////////////////////////////////////////////////////////////////////////////
//
// mapOrphanTransactions
//

bool AddOrphanTx(const CTransaction& tx)
{
    uint256 hash = tx.GetHash();
    if (mapOrphanTransactions.count(hash))
        return false;

    // Ignore big transactions, to avoid a
    // send-big-orphans memory exhaustion attack. If a peer has a legitimate
    // large transaction with a missing parent then we assume
    // it will rebroadcast it later, after the parent transaction(s)
    // have been mined or received.
    // 10,000 orphans, each of which is at most 5,000 bytes big is
    // at most 500 megabytes of orphans:
    unsigned int sz = tx.GetSerializeSize(SER_NETWORK, CTransaction::CURRENT_VERSION);
    if (sz > 5000)
    {
        printf("ignoring large orphan tx (size: %u, hash: %s)\n", sz, hash.ToString().c_str());
        return false;
    }

    mapOrphanTransactions[hash] = tx;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
        mapOrphanTransactionsByPrev[txin.prevout.hash].insert(hash);

    printf("stored orphan tx %s (mapsz %" PRIszu")\n", hash.ToString().c_str(),
        mapOrphanTransactions.size());
    return true;
}

void static EraseOrphanTx(uint256 hash)
{
    if (!mapOrphanTransactions.count(hash))
        return;
    const CTransaction& tx = mapOrphanTransactions[hash];
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        mapOrphanTransactionsByPrev[txin.prevout.hash].erase(hash);
        if (mapOrphanTransactionsByPrev[txin.prevout.hash].empty())
            mapOrphanTransactionsByPrev.erase(txin.prevout.hash);
    }
    mapOrphanTransactions.erase(hash);
}

unsigned int LimitOrphanTxSize(unsigned int nMaxOrphans)
{
    unsigned int nEvicted = 0;
    while (mapOrphanTransactions.size() > nMaxOrphans)
    {
        // Evict a random orphan:
        uint256 randomhash = GetRandHash();
        map<uint256, CTransaction>::iterator it = mapOrphanTransactions.lower_bound(randomhash);
        if (it == mapOrphanTransactions.end())
            it = mapOrphanTransactions.begin();
        EraseOrphanTx(it->first);
        ++nEvicted;
    }
    return nEvicted;
}







//////////////////////////////////////////////////////////////////////////////
//
// CTransaction / CTxOut
//

bool CTxOut::IsDust() const
{
    // Crypto: IsDust() detection disabled, allows any valid dust to be relayed.
    // The fees imposed on each dust txo is considered sufficient spam deterrant.
    return false;
}

bool CTransaction::IsStandard(string& strReason) const
{
    if (nVersion > CTransaction::CURRENT_VERSION || nVersion < 1) {
        strReason = "version";
        return false;
    }

    if (!IsFinal()) {
        strReason = "not-final";
        return false;
    }

    // Extremely large transactions with lots of inputs can cost the network
    // almost as much to process as they cost the sender in fees, because
    // computing signature hashes is O(ninputs*txsize). Limiting transactions
    // to MAX_STANDARD_TX_SIZE mitigates CPU exhaustion attacks.
    unsigned int sz = this->GetSerializeSize(SER_NETWORK, CTransaction::CURRENT_VERSION);
    if (sz >= MAX_STANDARD_TX_SIZE) {
        strReason = "tx-size";
        return false;
    }

    BOOST_FOREACH(const CTxIn& txin, vin)
    {
        // Biggest 'standard' txin is a 3-signature 3-of-3 CHECKMULTISIG
        // pay-to-script-hash, which is 3 ~80-byte signatures, 3
        // ~65-byte public keys, plus a few script ops.
        if (txin.scriptSig.size() > 500) {
            strReason = "scriptsig-size";
            return false;
        }
        if (!txin.scriptSig.IsPushOnly()) {
            strReason = "scriptsig-not-pushonly";
            return false;
        }
        if (!txin.scriptSig.HasCanonicalPushes()) {
            strReason = "non-canonical-push";
            return false;
        }
    }
    unsigned int nDataOut = 0;
    txnouttype whichType;
    BOOST_FOREACH(const CTxOut& txout, vout) {
        if (!::IsStandard(txout.scriptPubKey, whichType)) {
            strReason = "scriptpubkey";
            return false;
        }
        if (whichType == TX_NULL_DATA)
            nDataOut++;
        else if (txout.IsDust()) {
            strReason = "dust";
            return false;
        }
    }

    // only one OP_RETURN txout is permitted
    if (nDataOut > 1) {
        strReason = "multi-op-return";
        return false;
    }

    return true;
}


//
// Check transaction inputs, and make sure any
// pay-to-script-hash transactions are evaluating IsStandard scripts
//
// Why bother? To avoid denial-of-service attacks; an attacker
// can submit a standard HASH... OP_EQUAL transaction,
// which will get accepted into blocks. The redemption
// script can be anything; an attacker could use a very
// expensive-to-check-upon-redemption script like:
//   DUP CHECKSIG DROP ... repeated 100 times... OP_1
//
bool CTransaction::AreInputsStandard(CCoinsViewCache& mapInputs) const
{
    if (IsCoinBase())
        return true; // Coinbases don't use vin normally

    for (unsigned int i = 0; i < vin.size(); i++)
    {
        const CTxOut& prev = GetOutputFor(vin[i], mapInputs);

        vector<vector<unsigned char> > vSolutions;
        txnouttype whichType;
        // get the scriptPubKey corresponding to this input:
        const CScript& prevScript = prev.scriptPubKey;
        if (!Solver(prevScript, whichType, vSolutions))
            return false;
        int nArgsExpected = ScriptSigArgsExpected(whichType, vSolutions);
        if (nArgsExpected < 0)
            return false;

        // Transactions with extra stuff in their scriptSigs are
        // non-standard. Note that this EvalScript() call will
        // be quick, because if there are any operations
        // beside "push data" in the scriptSig the
        // IsStandard() call returns false
        vector<vector<unsigned char> > stack;
        if (!EvalScript(stack, vin[i].scriptSig, *this, i, false, 0))
            return false;

        if (whichType == TX_SCRIPTHASH)
        {
            if (stack.empty())
                return false;
            CScript subscript(stack.back().begin(), stack.back().end());
            vector<vector<unsigned char> > vSolutions2;
            txnouttype whichType2;
            if (!Solver(subscript, whichType2, vSolutions2))
                return false;
            if (whichType2 == TX_SCRIPTHASH)
                return false;

            int tmpExpected;
            tmpExpected = ScriptSigArgsExpected(whichType2, vSolutions2);
            if (tmpExpected < 0)
                return false;
            nArgsExpected += tmpExpected;
        }

        if (stack.size() != (unsigned int)nArgsExpected)
            return false;
    }

    return true;
}

unsigned int CTransaction::GetLegacySigOpCount() const
{
    unsigned int nSigOps = 0;
    BOOST_FOREACH(const CTxIn& txin, vin)
    {
        nSigOps += txin.scriptSig.GetSigOpCount(false);
    }
    BOOST_FOREACH(const CTxOut& txout, vout)
    {
        nSigOps += txout.scriptPubKey.GetSigOpCount(false);
    }
    return nSigOps;
}


int CMerkleTx::SetMerkleBranch(const CBlock* pblock)
{
    CBlock blockTmp;

    if (pblock == NULL) {
        CCoins coins;
        if (pcoinsTip->GetCoins(GetHash(), coins)) {
            CBlockIndex *pindex = FindBlockByHeight(coins.nHeight);
            if (pindex) {
                if (!blockTmp.ReadFromDisk(pindex))
                    return 0;
                pblock = &blockTmp;
            }
        }
    }

    if (pblock) {
        // Update the tx's hashBlock
        hashBlock = pblock->GetHash();

        // Locate the transaction
        for (nIndex = 0; nIndex < (int)pblock->vtx.size(); nIndex++)
            if (pblock->vtx[nIndex] == *(CTransaction*)this)
                break;
        if (nIndex == (int)pblock->vtx.size())
        {
            vMerkleBranch.clear();
            nIndex = -1;
            printf("ERROR: SetMerkleBranch() : couldn't find tx in block\n");
            return 0;
        }

        // Fill in merkle branch
        vMerkleBranch = pblock->GetMerkleBranch(nIndex);
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







bool CTransaction::CheckTransaction(CValidationState &state) const
{
    // Basic checks that don't depend on any context
    if (vin.empty())
        return state.DoS(10, error("CTransaction::CheckTransaction() : vin empty"));
    if (vout.empty())
        return state.DoS(10, error("CTransaction::CheckTransaction() : vout empty"));
    // Size limits
    if (::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION) > MAX_BLOCK_SIZE)
        return state.DoS(100, error("CTransaction::CheckTransaction() : size limits failed"));

    // Check for negative or overflow output values
    int64 nValueOut = 0;
    BOOST_FOREACH(const CTxOut& txout, vout)
    {
        if (txout.nValue < 0)
            return state.DoS(100, error("CTransaction::CheckTransaction() : txout.nValue negative"));
        if (txout.nValue > MAX_MONEY)
            return state.DoS(100, error("CTransaction::CheckTransaction() : txout.nValue too high"));
        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut))
            return state.DoS(100, error("CTransaction::CheckTransaction() : txout total out of range"));
    }

    // Check for duplicate inputs
    set<COutPoint> vInOutPoints;
    BOOST_FOREACH(const CTxIn& txin, vin)
    {
        if (vInOutPoints.count(txin.prevout))
            return state.DoS(100, error("CTransaction::CheckTransaction() : duplicate inputs"));
        vInOutPoints.insert(txin.prevout);
    }

    if (IsCoinBase())
    {
        if (vin[0].scriptSig.size() < 2 || vin[0].scriptSig.size() > 1000)
            return state.DoS(1000, error("CTransaction::CheckTransaction() : coinbase script size"));
    }
    else
    {
        BOOST_FOREACH(const CTxIn& txin, vin)
            if (txin.prevout.IsNull())
                return state.DoS(10, error("CTransaction::CheckTransaction() : prevout is null"));
    }

    return true;
}

int64 CTransaction::GetMinFee(unsigned int nBlockSize, bool fAllowFree,
                              enum GetMinFee_mode mode) const
{
    // Base fee is either nMinTxFee or nMinRelayTxFee
    int64 nBaseFee = (mode == GMF_RELAY) ? nMinRelayTxFee : nMinTxFee;

    unsigned int nBytes = ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION);
    unsigned int nNewBlockSize = nBlockSize + nBytes;
    int64 nMinFee = (1 + (int64)nBytes / 1000) * nBaseFee;

    if (fAllowFree)
    {
        // There is a free transaction area in blocks created by most miners,
        // * If we are relaying we allow transactions up to DEFAULT_BLOCK_PRIORITY_SIZE - 1000
        //   to be considered to fall into this category. We don't want to encourage sending
        //   multiple transactions instead of one big transaction to avoid fees.
        // * If we are creating a transaction we allow transactions up to 5,000 bytes
        //   to be considered safe and assume they can likely make it into this section.
        if (nBytes < (mode == GMF_SEND ? 5000 : (DEFAULT_BLOCK_PRIORITY_SIZE - 1000)))
            nMinFee = 0;
    }

    // Crypto
    // To limit dust spam, add nBaseFee for each output less than DUST_SOFT_LIMIT
    BOOST_FOREACH(const CTxOut& txout, vout)
        if (txout.nValue < DUST_SOFT_LIMIT)
            nMinFee += nBaseFee;

    // Raise the price as the block approaches full
    if (nBlockSize != 1 && nNewBlockSize >= MAX_BLOCK_SIZE_GEN/2)
    {
        if (nNewBlockSize >= MAX_BLOCK_SIZE_GEN)
            return MAX_MONEY;
        nMinFee *= MAX_BLOCK_SIZE_GEN / (MAX_BLOCK_SIZE_GEN - nNewBlockSize);
    }

    if (!MoneyRange(nMinFee))
        nMinFee = MAX_MONEY;
    return nMinFee;
}

void CTxMemPool::pruneSpent(const uint256 &hashTx, CCoins &coins)
{
    LOCK(cs);

    std::map<COutPoint, CInPoint>::iterator it = mapNextTx.lower_bound(COutPoint(hashTx, 0));

    // iterate over all COutPoints in mapNextTx whose hash equals the provided hashTx
    while (it != mapNextTx.end() && it->first.hash == hashTx) {
        coins.Spend(it->first.n); // and remove those outputs from coins
        it++;
    }
}

bool CTxMemPool::accept(CValidationState &state, CTransaction &tx, bool fCheckInputs, bool fLimitFree,
                        bool* pfMissingInputs, bool fRejectInsaneFee)
{
    if (pfMissingInputs)
        *pfMissingInputs = false;

    if (!tx.CheckTransaction(state))
        return error("CTxMemPool::accept() : CheckTransaction failed");

    // Coinbase is only valid in a block, not as a loose transaction
    if (tx.IsCoinBase())
        return state.DoS(100, error("CTxMemPool::accept() : coinbase as individual tx"));

    // To help v0.1.5 clients who would see it as a negative number
    if ((int64)tx.nLockTime > std::numeric_limits<int>::max())
        return error("CTxMemPool::accept() : not accepting nLockTime beyond 2038 yet");

    // Rather not work on nonstandard transactions (unless -testnet)
    string strNonStd;
    if (!fTestNet && !tx.IsStandard(strNonStd))
        return error("CTxMemPool::accept() : nonstandard transaction (%s)",
                     strNonStd.c_str());

    // is it already in the memory pool?
    uint256 hash = tx.GetHash();
    {
        LOCK(cs);
        if (mapTx.count(hash))
            return false;
    }

    // Check for conflicts with in-memory transactions
    CTransaction* ptxOld = NULL;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        COutPoint outpoint = tx.vin[i].prevout;
        if (mapNextTx.count(outpoint))
        {
            // Disable replacement feature for now
            return false;

            // Allow replacing with a newer version of the same transaction
            if (i != 0)
                return false;
            ptxOld = mapNextTx[outpoint].ptx;
            if (ptxOld->IsFinal())
                return false;
            if (!tx.IsNewerThan(*ptxOld))
                return false;
            for (unsigned int i = 0; i < tx.vin.size(); i++)
            {
                COutPoint outpoint = tx.vin[i].prevout;
                if (!mapNextTx.count(outpoint) || mapNextTx[outpoint].ptx != ptxOld)
                    return false;
            }
            break;
        }
    }

    if (fCheckInputs)
    {
        CCoinsView dummy;
        CCoinsViewCache view(dummy);

        {
        LOCK(cs);
        CCoinsViewMemPool viewMemPool(*pcoinsTip, *this);
        view.SetBackend(viewMemPool);

        // do we already have it?
        if (view.HaveCoins(hash))
            return false;

        // do all inputs exist?
        // Note that this does not check for the presence of actual outputs (see the next check for that),
        // only helps filling in pfMissingInputs (to determine missing vs spent).
        BOOST_FOREACH(const CTxIn txin, tx.vin) {
            if (!view.HaveCoins(txin.prevout.hash)) {
                if (pfMissingInputs)
                    *pfMissingInputs = true;
                return false;
            }
        }

        // are the actual inputs available?
        if (!tx.HaveInputs(view))
            return state.Invalid(error("CTxMemPool::accept() : inputs already spent"));

        // Bring the best block into scope
        view.GetBestBlock();

        // we have all inputs cached now, so switch back to dummy, so we don't need to keep lock on mempool
        view.SetBackend(dummy);
        }

        // Check for non-standard pay-to-script-hash in inputs
        if (!tx.AreInputsStandard(view) && !fTestNet)
            return error("CTxMemPool::accept() : nonstandard transaction input");

        // Note: if you modify this code to accept non-standard transactions, then
        // you should add code here to check that the transaction does a
        // reasonable number of ECDSA signature verifications.

        int64 nFees = tx.GetValueIn(view)-tx.GetValueOut();
        unsigned int nSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);

        // Don't accept it if it can't get into a block
        int64 txMinFee = tx.GetMinFee(1000, true, GMF_RELAY);
        if (fLimitFree && nFees < txMinFee)
            return error("CTxMemPool::accept() : not enough fees %s, %" PRI64d" < %" PRI64d,
                         hash.ToString().c_str(),
                         nFees, txMinFee);

        // Continuously rate-limit free transactions
        // This mitigates 'penny-flooding' -- sending thousands of free transactions just to
        // be annoying or make others' transactions take longer to confirm.
        if (fLimitFree && nFees < CTransaction::nMinRelayTxFee)
        {
            static double dFreeCount;
            static int64 nLastTime;
            int64 nNow = GetTime();

            LOCK(cs);

            // Use an exponentially decaying ~10-minute window:
            dFreeCount *= pow(1.0 - 1.0/600.0, (double)(nNow - nLastTime));
            nLastTime = nNow;
            // -limitfreerelay unit is thousand-bytes-per-minute
            // At default rate it would take over a month to fill 1GB
            if (dFreeCount >= GetArg("-limitfreerelay", 15)*10*1000)
                return error("CTxMemPool::accept() : free transaction rejected by rate limiter");
            if (fDebug)
                printf("Rate limit dFreeCount: %g => %g\n", dFreeCount, dFreeCount+nSize);
            dFreeCount += nSize;
        }

        if (fRejectInsaneFee && nFees > CTransaction::nMinRelayTxFee * 1000)
            return error("CTxMemPool::accept() : insane fees %s, %" PRI64d" > %" PRI64d,
                         hash.ToString().c_str(),
                         nFees, CTransaction::nMinRelayTxFee * 1000);

        // Check against previous transactions
        // This is done last to help prevent CPU exhaustion denial-of-service attacks.
        if (!tx.CheckInputs(state, view, true, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC))
        {
            return error("CTxMemPool::accept() : ConnectInputs failed %s", hash.ToString().c_str());
        }
    }

    // Store transaction in memory
    {
        LOCK(cs);
        if (ptxOld)
        {
            printf("CTxMemPool::accept() : replacing tx %s with new version\n", ptxOld->GetHash().ToString().c_str());
            remove(*ptxOld);
        }
        addUnchecked(hash, tx);
    }

    ///// are we sure this is ok when loading transactions or restoring block txes
    // If updated, erase old tx from wallet
    if (ptxOld)
        EraseFromWallets(ptxOld->GetHash());
    SyncWithWallets(hash, tx, NULL, true);

    return true;
}

bool CTransaction::AcceptToMemoryPool(CValidationState &state, bool fCheckInputs, bool fLimitFree, bool* pfMissingInputs, bool fRejectInsaneFee)
{
    try {
        return mempool.accept(state, *this, fCheckInputs, fLimitFree, pfMissingInputs, fRejectInsaneFee);
    } catch(std::runtime_error &e) {
        return state.Abort(_("System error: ") + e.what());
    }
}

bool CTxMemPool::addUnchecked(const uint256& hash, const CTransaction &tx)
{
    // Add to memory pool without checking anything.  Don't call this directly,
    // call CTxMemPool::accept to properly check the transaction first.
    {
        mapTx[hash] = tx;
        for (unsigned int i = 0; i < tx.vin.size(); i++)
            mapNextTx[tx.vin[i].prevout] = CInPoint(&mapTx[hash], i);
        nTransactionsUpdated++;
    }
    return true;
}


bool CTxMemPool::remove(const CTransaction &tx, bool fRecursive)
{
    // Remove transaction from memory pool
    {
        LOCK(cs);
        uint256 hash = tx.GetHash();
        if (fRecursive) {
            for (unsigned int i = 0; i < tx.vout.size(); i++) {
                std::map<COutPoint, CInPoint>::iterator it = mapNextTx.find(COutPoint(hash, i));
                if (it != mapNextTx.end())
                    remove(*it->second.ptx, true);
            }
        }
        if (mapTx.count(hash))
        {
            BOOST_FOREACH(const CTxIn& txin, tx.vin)
                mapNextTx.erase(txin.prevout);
            mapTx.erase(hash);
            nTransactionsUpdated++;
        }
    }
    return true;
}

bool CTxMemPool::removeConflicts(const CTransaction &tx)
{
    // Remove transactions which depend on inputs of tx, recursively
    LOCK(cs);
    BOOST_FOREACH(const CTxIn &txin, tx.vin) {
        std::map<COutPoint, CInPoint>::iterator it = mapNextTx.find(txin.prevout);
        if (it != mapNextTx.end()) {
            const CTransaction &txConflict = *it->second.ptx;
            if (txConflict != tx)
                remove(txConflict, true);
        }
    }
    return true;
}

void CTxMemPool::clear()
{
    LOCK(cs);
    mapTx.clear();
    mapNextTx.clear();
    ++nTransactionsUpdated;
}

void CTxMemPool::queryHashes(std::vector<uint256>& vtxid)
{
    vtxid.clear();

    LOCK(cs);
    vtxid.reserve(mapTx.size());
    for (map<uint256, CTransaction>::iterator mi = mapTx.begin(); mi != mapTx.end(); ++mi)
        vtxid.push_back((*mi).first);
}




int CMerkleTx::GetDepthInMainChainINTERNAL(CBlockIndex* &pindexRet) const
{
    if (hashBlock == 0 || nIndex == -1)
        return 0;

    // Find the block it claims to be in
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain())
        return 0;

    // Make sure the merkle branch connects to this block
    if (!fMerkleVerified)
    {
        if (CBlock::CheckMerkleBranch(GetHash(), vMerkleBranch, nIndex) != pindex->hashMerkleRoot)
            return 0;
        fMerkleVerified = true;
    }

    pindexRet = pindex;
    return pindexBest->nHeight - pindex->nHeight + 1;
}

int CMerkleTx::GetDepthInMainChain(CBlockIndex* &pindexRet) const
{
    int nResult = GetDepthInMainChainINTERNAL(pindexRet);
    if (nResult == 0 && !mempool.exists(GetHash()))
        return -1; // Not in chain, not in mempool

    return nResult;
}

int CMerkleTx::GetBlocksToMaturity() const
{
    if (!IsCoinBase())
        return 0;
    return max(0, (COINBASE_MATURITY+20) - GetDepthInMainChain());
}


bool CMerkleTx::AcceptToMemoryPool(bool fCheckInputs, bool fLimitFree)
{
    CValidationState state;
    return CTransaction::AcceptToMemoryPool(state, fCheckInputs, fLimitFree);
}



bool CWalletTx::AcceptWalletTransaction(bool fCheckInputs)
{
    {
        LOCK(mempool.cs);
        // Add previous supporting transactions first
        BOOST_FOREACH(CMerkleTx& tx, vtxPrev)
        {
            if (!tx.IsCoinBase())
            {
                uint256 hash = tx.GetHash();
                if (!mempool.exists(hash) && pcoinsTip->HaveCoins(hash))
                    tx.AcceptToMemoryPool(fCheckInputs, false);
            }
        }
        return AcceptToMemoryPool(fCheckInputs, false);
    }
    return false;
}


// Return transaction in tx, and if it was found inside a block, its hash is placed in hashBlock
bool GetTransaction(const uint256 &hash, CTransaction &txOut, uint256 &hashBlock, bool fAllowSlow)
{
    CBlockIndex *pindexSlow = NULL;
    {
        LOCK(cs_main);
        {
            LOCK(mempool.cs);
            if (mempool.exists(hash))
            {
                txOut = mempool.lookup(hash);
                return true;
            }
        }

        if (fTxIndex) {
            CDiskTxPos postx;
            if (pblocktree->ReadTxIndex(hash, postx)) {
                CAutoFile file(OpenBlockFile(postx, true), SER_DISK, CLIENT_VERSION);
                CBlockHeader header;
                try {
                    file >> header;
                    fseek(file, postx.nTxOffset, SEEK_CUR);
                    file >> txOut;
                } catch (std::exception &e) {
                    return error("%s() : deserialize or I/O error", __PRETTY_FUNCTION__);
                }
                hashBlock = header.GetHash();
                if (txOut.GetHash() != hash)
                    return error("%s() : txid mismatch", __PRETTY_FUNCTION__);
                return true;
            }
        }

        if (fAllowSlow) { // use coin database to locate block that contains transaction, and scan it
            int nHeight = -1;
            {
                CCoinsViewCache &view = *pcoinsTip;
                CCoins coins;
                if (view.GetCoins(hash, coins))
                    nHeight = coins.nHeight;
            }
            if (nHeight > 0)
                pindexSlow = FindBlockByHeight(nHeight);
        }
    }

    if (pindexSlow) {
        CBlock block;
        if (block.ReadFromDisk(pindexSlow)) {
            BOOST_FOREACH(const CTransaction &tx, block.vtx) {
                if (tx.GetHash() == hash) {
                    txOut = tx;
                    hashBlock = pindexSlow->GetBlockHash();
                    return true;
                }
            }
        }
    }

    return false;
}






//////////////////////////////////////////////////////////////////////////////
//
// CBlock and CBlockIndex
//

static CBlockIndex* pblockindexFBBHLast;
CBlockIndex* FindBlockByHeight(int nHeight)
{
    CBlockIndex *pblockindex;
    if (nHeight < nBestHeight / 2)
        pblockindex = pindexGenesisBlock;
    else
        pblockindex = pindexBest;
    if (pblockindexFBBHLast && abs(nHeight - pblockindex->nHeight) > abs(nHeight - pblockindexFBBHLast->nHeight))
        pblockindex = pblockindexFBBHLast;
    while (pblockindex->nHeight > nHeight)
        pblockindex = pblockindex->pprev;
    while (pblockindex->nHeight < nHeight)
        pblockindex = pblockindex->pnext;
    pblockindexFBBHLast = pblockindex;
    return pblockindex;
}

bool CBlock::ReadFromDisk(const CBlockIndex* pindex)
{
	LastHeight = pindex->nHeight - 1;
    if (!ReadFromDisk(pindex->GetBlockPos()))
        return false;
    if (GetHash() != pindex->GetBlockHash())
        return error("CBlock::ReadFromDisk() : GetHash() doesn't match index");
    return true;
}

uint256 static GetOrphanRoot(const CBlockHeader* pblock)
{
    // Work back to the first block in the orphan chain
    while (mapOrphanBlocks.count(pblock->hashPrevBlock))
        pblock = mapOrphanBlocks[pblock->hashPrevBlock];
    return pblock->GetHash();
}

// yacoin: increasing Nfactor gradually
const unsigned char minNfactor = 10;
const unsigned char maxNfactor = 30;

unsigned char GetNfactor(int64 nTimestamp) {
    int l = 0;

    if (nTimestamp <= nChainStartTime)
        return minNfactor;

    int64 s = nTimestamp - nChainStartTime;
    while ((s >> 1) > 3) {
      l += 1;
      s >>= 1;
    }

    s &= 3;

    int n = (l * 158 + s * 28 - 2670) / 100;

    if (n < 0) n = 0;

    if (n > 255)
        printf( "GetNfactor(%lld) - something wrong(n == %d)\n", nTimestamp, n );

    unsigned char N = (unsigned char) n;
    //printf("GetNfactor: %d -> %d %d : %d / %d\n", nTimestamp - nChainStartTime, l, s, n, min(max(N, minNfactor), maxNfactor));

    return min(max(N, minNfactor), maxNfactor); //Oh lords... Too lazy to remove this... Sorry xD Doesn't hurt the program tho...
}


int64 static GetBlockValue(int nHeight, int64 nFees)
{
    int64 nSubsidy = 5 * COIN;

 //Values entered manually, so they can be changed according to inflation//   

    if(nHeight == 1) {               
        nSubsidy = 16980.27397  * COIN;    //Premine - approx 0.025%
    } else if(nHeight < 28800) {
        nSubsidy = 5 * COIN;
    } else if(nHeight < 57600) {  
        nSubsidy = 4.99452055   * COIN;
    } else if(nHeight < 86400) {  
        nSubsidy = 4.98904110   * COIN;
    } else if(nHeight < 115200) {  
        nSubsidy = 4.98356164   * COIN;
    } else if(nHeight < 144000) {  
        nSubsidy = 4.97808219   * COIN;
    } else if(nHeight < 172800) {  
        nSubsidy = 4.97260274   * COIN;
    } else if(nHeight < 201600) {  
        nSubsidy = 4.96712329   * COIN;
    } else if(nHeight < 230400) {  
        nSubsidy = 4.96164384   * COIN;
    } else if(nHeight < 259200) {  
        nSubsidy = 4.95616438   * COIN;
    } else if(nHeight < 288000) {  
        nSubsidy = 4.95068493   * COIN;
    } else if(nHeight < 316800) {  
        nSubsidy = 4.94520548   * COIN;
    } else if(nHeight < 345600) {  
        nSubsidy = 4.93972603   * COIN;
    } else if(nHeight < 374400) {  
        nSubsidy = 4.93424658   * COIN;
    } else if(nHeight < 403200) {  
        nSubsidy = 4.92876712   * COIN;
    } else if(nHeight < 432000) {  
        nSubsidy = 4.92328767   * COIN;
    } else if(nHeight < 460800) {  
        nSubsidy = 4.91780822   * COIN;
    } else if(nHeight < 489600) {  
        nSubsidy = 4.91232877   * COIN;
    } else if(nHeight < 518400) {  
        nSubsidy = 4.90684932   * COIN;
    } else if(nHeight < 547200) {  
        nSubsidy = 4.90136986   * COIN;
    } else if(nHeight < 576000) {  
        nSubsidy = 4.89589041   * COIN;
    } else if(nHeight < 604800) {  
        nSubsidy = 4.89041096   * COIN;
    } else if(nHeight < 633600) {  
        nSubsidy = 4.88493151   * COIN;
    } else if(nHeight < 662400) {  
        nSubsidy = 4.87945205   * COIN;
    } else if(nHeight < 691200) {  
        nSubsidy = 4.87397260   * COIN;
    } else if(nHeight < 720000) {  
        nSubsidy = 4.86849315   * COIN;
    } else if(nHeight < 748800) {  
        nSubsidy = 4.86301370   * COIN;
    } else if(nHeight < 777600) {  
        nSubsidy = 4.85753425   * COIN;
    } else if(nHeight < 806400) {  
        nSubsidy = 4.85205479   * COIN;
    } else if(nHeight < 835200) {  
        nSubsidy = 4.84657534   * COIN;
    } else if(nHeight < 864000) {  
        nSubsidy = 4.84109589   * COIN;
    } else if(nHeight < 892800) {  
        nSubsidy = 4.83561644   * COIN;
    } else if(nHeight < 921600) {  
        nSubsidy = 4.83013699   * COIN;
    } else if(nHeight < 950400) {  
        nSubsidy = 4.82465753   * COIN;
    } else if(nHeight < 979200) {  
        nSubsidy = 4.81917808   * COIN;
    } else if(nHeight < 1008000) {  
        nSubsidy = 4.81369863   * COIN;
    } else if(nHeight < 1036800) {  
        nSubsidy = 4.80821918   * COIN;
    } else if(nHeight < 1065600) {  
        nSubsidy = 4.80273973   * COIN;
    } else if(nHeight < 1094400) {  
        nSubsidy = 4.79726027   * COIN;
    } else if(nHeight < 1123200) {  
        nSubsidy = 4.79178082   * COIN;
    } else if(nHeight < 1152000) {  
        nSubsidy = 4.78630137   * COIN;
    } else if(nHeight < 1180800) {  
        nSubsidy = 4.78082192   * COIN;
    } else if(nHeight < 1209600) {  
        nSubsidy = 4.77534247   * COIN;
    } else if(nHeight < 1238400) {  
        nSubsidy = 4.76986301   * COIN;
    } else if(nHeight < 1267200) {  
        nSubsidy = 4.76438356   * COIN;
    } else if(nHeight < 1296000) {  
        nSubsidy = 4.75890411   * COIN;
    } else if(nHeight < 1324800) {  
        nSubsidy = 4.75342466   * COIN;
    } else if(nHeight < 1353600) {  
        nSubsidy = 4.74794521   * COIN;
    } else if(nHeight < 1382400) {  
        nSubsidy = 4.74246575   * COIN;
    } else if(nHeight < 1411200) {  
        nSubsidy = 4.73698630   * COIN;
    } else if(nHeight < 1440000) {  
        nSubsidy = 4.73150685   * COIN;
    } else if(nHeight < 1468800) {  
        nSubsidy = 4.72602740   * COIN;
    } else if(nHeight < 1497600) {  
        nSubsidy = 4.72054795   * COIN;
    } else if(nHeight < 1526400) {  
        nSubsidy = 4.71506849   * COIN;
    } else if(nHeight < 1555200) {  
        nSubsidy = 4.70958904   * COIN;
    } else if(nHeight < 1584000) {  
        nSubsidy = 4.70410959   * COIN;
    } else if(nHeight < 1612800) {  
        nSubsidy = 4.69863014   * COIN;
    } else if(nHeight < 1641600) {  
        nSubsidy = 4.69315068   * COIN;
    } else if(nHeight < 1670400) {  
        nSubsidy = 4.68767123   * COIN;
    } else if(nHeight < 1699200) {  
        nSubsidy = 4.68219178   * COIN;
    } else if(nHeight < 1728000) {  
        nSubsidy = 4.67671233   * COIN;
    } else if(nHeight < 1756800) {  
        nSubsidy = 4.67123288   * COIN;
    } else if(nHeight < 1785600) {  
        nSubsidy = 4.66575342   * COIN;
    } else if(nHeight < 1814400) {  
        nSubsidy = 4.66027397   * COIN;
    } else if(nHeight < 1843200) {  
        nSubsidy = 4.65479452   * COIN;
    } else if(nHeight < 1872000) {  
        nSubsidy = 4.64931507   * COIN;
    } else if(nHeight < 1900800) {  
        nSubsidy = 4.64383562   * COIN;
    } else if(nHeight < 1929600) {  
        nSubsidy = 4.63835616   * COIN;
    } else if(nHeight < 1958400) {  
        nSubsidy = 4.63287671   * COIN;
    } else if(nHeight < 1987200) {  
        nSubsidy = 4.62739726   * COIN;
    } else if(nHeight < 2016000) {  
        nSubsidy = 4.62191781   * COIN;
    } else if(nHeight < 2044800) {  
        nSubsidy = 4.61643836   * COIN;
    } else if(nHeight < 2073600) {  
        nSubsidy = 4.61095890   * COIN;
    } else if(nHeight < 2102400) {  
        nSubsidy = 4.60547945   * COIN;
    } else if(nHeight < 2131200) {  
        nSubsidy = 4.60000000   * COIN;
    } else if(nHeight < 2160000) {  
        nSubsidy = 4.59452055   * COIN;
    } else if(nHeight < 2188800) {  
        nSubsidy = 4.58904110   * COIN;
    } else if(nHeight < 2217600) {  
        nSubsidy = 4.58356164   * COIN;
    } else if(nHeight < 2246400) {  
        nSubsidy = 4.57808219   * COIN;
    } else if(nHeight < 2275200) {  
        nSubsidy = 4.57260274   * COIN;
    } else if(nHeight < 2304000) {  
        nSubsidy = 4.56712329   * COIN;
    } else if(nHeight < 2332800) {  
        nSubsidy = 4.56164384   * COIN;
    } else if(nHeight < 2361600) {  
        nSubsidy = 4.55616438   * COIN;
    } else if(nHeight < 2390400) {  
        nSubsidy = 4.55068493   * COIN;
    } else if(nHeight < 2419200) {  
        nSubsidy = 4.54520548   * COIN;
    } else if(nHeight < 2448000) {  
        nSubsidy = 4.53972603   * COIN;
    } else if(nHeight < 2476800) {  
        nSubsidy = 4.53424658   * COIN;
    } else if(nHeight < 2505600) {  
        nSubsidy = 4.52876712   * COIN;
    } else if(nHeight < 2534400) {  
        nSubsidy = 4.52328767   * COIN;
    } else if(nHeight < 2563200) {  
        nSubsidy = 4.51780822   * COIN;
    } else if(nHeight < 2592000) {  
        nSubsidy = 4.51232877   * COIN;
    } else if(nHeight < 2620800) {  
        nSubsidy = 4.50684932   * COIN;
    } else if(nHeight < 2649600) {  
        nSubsidy = 4.50136986   * COIN;
    } else if(nHeight < 2678400) {  
        nSubsidy = 4.49589041   * COIN;
    } else if(nHeight < 2707200) {  
        nSubsidy = 4.49041096   * COIN;
    } else if(nHeight < 2736000) {  
        nSubsidy = 4.48493151   * COIN;
    } else if(nHeight < 2764800) {  
        nSubsidy = 4.47945205   * COIN;
    } else if(nHeight < 2793600) {  
        nSubsidy = 4.47397260   * COIN;
    } else if(nHeight < 2822400) {  
        nSubsidy = 4.46849315   * COIN;
    } else if(nHeight < 2851200) {  
        nSubsidy = 4.46301370   * COIN;
    } else if(nHeight < 2880000) {  
        nSubsidy = 4.45753425   * COIN;
    } else if(nHeight < 2908800) {  
        nSubsidy = 4.45205479   * COIN;
    } else if(nHeight < 2937600) {  
        nSubsidy = 4.44657534   * COIN;
    } else if(nHeight < 2966400) {  
        nSubsidy = 4.44109589   * COIN;
    } else if(nHeight < 2995200) {  
        nSubsidy = 4.43561644   * COIN;
    } else if(nHeight < 3024000) {  
        nSubsidy = 4.43013699   * COIN;
    } else if(nHeight < 3052800) {  
        nSubsidy = 4.42465753   * COIN;
    } else if(nHeight < 3081600) {  
        nSubsidy = 4.41917808   * COIN;
    } else if(nHeight < 3110400) {  
        nSubsidy = 4.41369863   * COIN;
    } else if(nHeight < 3139200) {  
        nSubsidy = 4.40821918   * COIN;
    } else if(nHeight < 3168000) {  
        nSubsidy = 4.40273973   * COIN;
    } else if(nHeight < 3196800) {  
        nSubsidy = 4.39726027   * COIN;
    } else if(nHeight < 3225600) {  
        nSubsidy = 4.39178082   * COIN;
    } else if(nHeight < 3254400) {  
        nSubsidy = 4.38630137   * COIN;
    } else if(nHeight < 3283200) {  
        nSubsidy = 4.38082192   * COIN;
    } else if(nHeight < 3312000) {  
        nSubsidy = 4.37534247   * COIN;
    } else if(nHeight < 3340800) {  
        nSubsidy = 4.36986301   * COIN;
    } else if(nHeight < 3369600) {  
        nSubsidy = 4.36438356   * COIN;
    } else if(nHeight < 3398400) {  
        nSubsidy = 4.35890411   * COIN;
    } else if(nHeight < 3427200) {  
        nSubsidy = 4.35342466   * COIN;
    } else if(nHeight < 3456000) {  
        nSubsidy = 4.34794521   * COIN;
    } else if(nHeight < 3484800) {  
        nSubsidy = 4.34246575   * COIN;
    } else if(nHeight < 3513600) {  
        nSubsidy = 4.33698630   * COIN;
    } else if(nHeight < 3542400) {  
        nSubsidy = 4.33150685   * COIN;
    } else if(nHeight < 3571200) {  
        nSubsidy = 4.32602740   * COIN;
    } else if(nHeight < 3600000) {  
        nSubsidy = 4.32054795   * COIN;
    } else if(nHeight < 3628800) {  
        nSubsidy = 4.31506849   * COIN;
    } else if(nHeight < 3657600) {  
        nSubsidy = 4.30958904   * COIN;
    } else if(nHeight < 3686400) {  
        nSubsidy = 4.30410959   * COIN;
    } else if(nHeight < 3715200) {  
        nSubsidy = 4.29863014   * COIN;
    } else if(nHeight < 3744000) {  
        nSubsidy = 4.29315068   * COIN;
    } else if(nHeight < 3772800) {  
        nSubsidy = 4.28767123   * COIN;
    } else if(nHeight < 3801600) {  
        nSubsidy = 4.28219178   * COIN;
    } else if(nHeight < 3830400) {  
        nSubsidy = 4.27671233   * COIN;
    } else if(nHeight < 3859200) {  
        nSubsidy = 4.27123288   * COIN;
    } else if(nHeight < 3888000) {  
        nSubsidy = 4.26575342   * COIN;
    } else if(nHeight < 3916800) {  
        nSubsidy = 4.26027397   * COIN;
    } else if(nHeight < 3945600) {  
        nSubsidy = 4.25479452   * COIN;
    } else if(nHeight < 3974400) {  
        nSubsidy = 4.24931507   * COIN;
    } else if(nHeight < 4003200) {  
        nSubsidy = 4.24383562   * COIN;
    } else if(nHeight < 4032000) {  
        nSubsidy = 4.23835616   * COIN;
    } else if(nHeight < 4060800) {  
        nSubsidy = 4.23287671   * COIN;
    } else if(nHeight < 4089600) {  
        nSubsidy = 4.22739726   * COIN;
    } else if(nHeight < 4118400) {  
        nSubsidy = 4.22191781   * COIN;
    } else if(nHeight < 4147200) {  
        nSubsidy = 4.21643836   * COIN;
    } else if(nHeight < 4176000) {  
        nSubsidy = 4.21095890   * COIN;
    } else if(nHeight < 4204800) {  
        nSubsidy = 4.20547945   * COIN;
    } else if(nHeight < 4233600) {  
        nSubsidy = 4.20000000   * COIN;
    } else if(nHeight < 4262400) {  
        nSubsidy = 4.19452055   * COIN;
    } else if(nHeight < 4291200) {  
        nSubsidy = 4.18904110   * COIN;
    } else if(nHeight < 4320000) {  
        nSubsidy = 4.18356164   * COIN;
    } else if(nHeight < 4348800) {  
        nSubsidy = 4.17808219   * COIN;
    } else if(nHeight < 4377600) {  
        nSubsidy = 4.17260274   * COIN;
    } else if(nHeight < 4406400) {  
        nSubsidy = 4.16712329   * COIN;
    } else if(nHeight < 4435200) {  
        nSubsidy = 4.16164384   * COIN;
    } else if(nHeight < 4464000) {  
        nSubsidy = 4.15616438   * COIN;
    } else if(nHeight < 4492800) {  
        nSubsidy = 4.15068493   * COIN;
    } else if(nHeight < 4521600) {  
        nSubsidy = 4.14520548   * COIN;
    } else if(nHeight < 4550400) {  
        nSubsidy = 4.13972603   * COIN;
    } else if(nHeight < 4579200) {  
        nSubsidy = 4.13424658   * COIN;
    } else if(nHeight < 4608000) {  
        nSubsidy = 4.12876712   * COIN;
    } else if(nHeight < 4636800) {  
        nSubsidy = 4.12328767   * COIN;
    } else if(nHeight < 4665600) {  
        nSubsidy = 4.11780822   * COIN;
    } else if(nHeight < 4694400) {  
        nSubsidy = 4.11232877   * COIN;
    } else if(nHeight < 4723200) {  
        nSubsidy = 4.10684932   * COIN;
    } else if(nHeight < 4752000) {  
        nSubsidy = 4.10136986   * COIN;
    } else if(nHeight < 4780800) {  
        nSubsidy = 4.09589041   * COIN;
    } else if(nHeight < 4809600) {  
        nSubsidy = 4.09041096   * COIN;
    } else if(nHeight < 4838400) {  
        nSubsidy = 4.08493151   * COIN;
    } else if(nHeight < 4867200) {  
        nSubsidy = 4.07945205   * COIN;
    } else if(nHeight < 4896000) {  
        nSubsidy = 4.07397260   * COIN;
    } else if(nHeight < 4924800) {  
        nSubsidy = 4.06849315   * COIN;
    } else if(nHeight < 4953600) {  
        nSubsidy = 4.06301370   * COIN;
    } else if(nHeight < 4982400) {  
        nSubsidy = 4.05753425   * COIN;
    } else if(nHeight < 5011200) {  
        nSubsidy = 4.05205479   * COIN;
    } else if(nHeight < 5040000) {  
        nSubsidy = 4.04657534   * COIN;
    } else if(nHeight < 5068800) {  
        nSubsidy = 4.04109589   * COIN;
    } else if(nHeight < 5097600) {  
        nSubsidy = 4.03561644   * COIN;
    } else if(nHeight < 5126400) {  
        nSubsidy = 4.03013699   * COIN;
    } else if(nHeight < 5155200) {  
        nSubsidy = 4.02465753   * COIN;
    } else if(nHeight < 5184000) {  
        nSubsidy = 4.01917808   * COIN;
    } else if(nHeight < 5212800) {  
        nSubsidy = 4.01369863   * COIN;
    } else if(nHeight < 5241600) {  
        nSubsidy = 4.00821918   * COIN;
    } else if(nHeight < 5270400) {  
        nSubsidy = 4.00273973   * COIN;
    } else if(nHeight < 5299200) {  
        nSubsidy = 3.99726027   * COIN;
    } else if(nHeight < 5328000) {  
        nSubsidy = 3.99178082   * COIN;
    } else if(nHeight < 5356800) {  
        nSubsidy = 3.98630137   * COIN;
    } else if(nHeight < 5385600) {  
        nSubsidy = 3.98082192   * COIN;
    } else if(nHeight < 5414400) {  
        nSubsidy = 3.97534247   * COIN;
    } else if(nHeight < 5443200) {  
        nSubsidy = 3.96986301   * COIN;
    } else if(nHeight < 5472000) {  
        nSubsidy = 3.96438356   * COIN;
    } else if(nHeight < 5500800) {  
        nSubsidy = 3.95890411   * COIN;
    } else if(nHeight < 5529600) {  
        nSubsidy = 3.95342466   * COIN;
    } else if(nHeight < 5558400) {  
        nSubsidy = 3.94794521   * COIN;
    } else if(nHeight < 5587200) {  
        nSubsidy = 3.94246575   * COIN;
    } else if(nHeight < 5616000) {  
        nSubsidy = 3.93698630   * COIN;
    } else if(nHeight < 5644800) {  
        nSubsidy = 3.93150685   * COIN;
    } else if(nHeight < 5673600) {  
        nSubsidy = 3.92602740   * COIN;
    } else if(nHeight < 5702400) {  
        nSubsidy = 3.92054795   * COIN;
    } else if(nHeight < 5731200) {  
        nSubsidy = 3.91506849   * COIN;
    } else if(nHeight < 5760000) {  
        nSubsidy = 3.90958904   * COIN;
    } else if(nHeight < 5788800) {  
        nSubsidy = 3.90410959   * COIN;
    } else if(nHeight < 5817600) {  
        nSubsidy = 3.89863014   * COIN;
    } else if(nHeight < 5846400) {  
        nSubsidy = 3.89315068   * COIN;
    } else if(nHeight < 5875200) {  
        nSubsidy = 3.88767123   * COIN;
    } else if(nHeight < 5904000) {  
        nSubsidy = 3.88219178   * COIN;
    } else if(nHeight < 5932800) {  
        nSubsidy = 3.87671233   * COIN;
    } else if(nHeight < 5961600) {  
        nSubsidy = 3.87123288   * COIN;
    } else if(nHeight < 5990400) {  
        nSubsidy = 3.86575342   * COIN;
    } else if(nHeight < 6019200) {  
        nSubsidy = 3.86027397   * COIN;
    } else if(nHeight < 6048000) {  
        nSubsidy = 3.85479452   * COIN;
    } else if(nHeight < 6076800) {  
        nSubsidy = 3.84931507   * COIN;
    } else if(nHeight < 6105600) {  
        nSubsidy = 3.84383562   * COIN;
    } else if(nHeight < 6134400) {  
        nSubsidy = 3.83835616   * COIN;
    } else if(nHeight < 6163200) {  
        nSubsidy = 3.83287671   * COIN;
    } else if(nHeight < 6192000) {  
        nSubsidy = 3.82739726   * COIN;
    } else if(nHeight < 6220800) {  
        nSubsidy = 3.82191781   * COIN;
    } else if(nHeight < 6249600) {  
        nSubsidy = 3.81643836   * COIN;
    } else if(nHeight < 6278400) {  
        nSubsidy = 3.81095890   * COIN;
    } else if(nHeight < 6307200) {  
        nSubsidy = 3.80547945   * COIN;
    } else if(nHeight < 6336000) {  
        nSubsidy = 3.80000000   * COIN;
    } else if(nHeight < 6364800) {  
        nSubsidy = 3.79452055   * COIN;
    } else if(nHeight < 6393600) {  
        nSubsidy = 3.78904110   * COIN;
    } else if(nHeight < 6422400) {  
        nSubsidy = 3.78356164   * COIN;
    } else if(nHeight < 6451200) {  
        nSubsidy = 3.77808219   * COIN;
    } else if(nHeight < 6480000) {  
        nSubsidy = 3.77260274   * COIN;
    } else if(nHeight < 6508800) {  
        nSubsidy = 3.76712329   * COIN;
    } else if(nHeight < 6537600) {  
        nSubsidy = 3.76164384   * COIN;
    } else if(nHeight < 6566400) {  
        nSubsidy = 3.75616438   * COIN;
    } else if(nHeight < 6595200) {  
        nSubsidy = 3.75068493   * COIN;
    } else if(nHeight < 6624000) {  
        nSubsidy = 3.74520548   * COIN;
    } else if(nHeight < 6652800) {  
        nSubsidy = 3.73972603   * COIN;
    } else if(nHeight < 6681600) {  
        nSubsidy = 3.73424658   * COIN;
    } else if(nHeight < 6710400) {  
        nSubsidy = 3.72876712   * COIN;
    } else if(nHeight < 6739200) {  
        nSubsidy = 3.72328767   * COIN;
    } else if(nHeight < 6768000) {  
        nSubsidy = 3.71780822   * COIN;
    } else if(nHeight < 6796800) {  
        nSubsidy = 3.71232877   * COIN;
    } else if(nHeight < 6825600) {  
        nSubsidy = 3.70684932   * COIN;
    } else if(nHeight < 6854400) {  
        nSubsidy = 3.70136986   * COIN;
    } else if(nHeight < 6883200) {  
        nSubsidy = 3.69589041   * COIN;
    } else if(nHeight < 6912000) {  
        nSubsidy = 3.69041096   * COIN;
    } else if(nHeight < 6940800) {  
        nSubsidy = 3.68493151   * COIN;
    } else if(nHeight < 6969600) {  
        nSubsidy = 3.67945205   * COIN;
    } else if(nHeight < 6998400) {  
        nSubsidy = 3.67397260   * COIN;
    } else if(nHeight < 7027200) {  
        nSubsidy = 3.66849315   * COIN;
    } else if(nHeight < 7056000) {  
        nSubsidy = 3.66301370   * COIN;
    } else if(nHeight < 7084800) {  
        nSubsidy = 3.65753425   * COIN;
    } else if(nHeight < 7113600) {  
        nSubsidy = 3.65205479   * COIN;
    } else if(nHeight < 7142400) {  
        nSubsidy = 3.64657534   * COIN;
    } else if(nHeight < 7171200) {  
        nSubsidy = 3.64109589   * COIN;
    } else if(nHeight < 7200000) {  
        nSubsidy = 3.63561644   * COIN;
    } else if(nHeight < 7228800) {  
        nSubsidy = 3.63013699   * COIN;
    } else if(nHeight < 7257600) {  
        nSubsidy = 3.62465753   * COIN;
    } else if(nHeight < 7286400) {  
        nSubsidy = 3.61917808   * COIN;
    } else if(nHeight < 7315200) {  
        nSubsidy = 3.61369863   * COIN;
    } else if(nHeight < 7344000) {  
        nSubsidy = 3.60821918   * COIN;
    } else if(nHeight < 7372800) {  
        nSubsidy = 3.60273973   * COIN;
    } else if(nHeight < 7401600) {  
        nSubsidy = 3.59726027   * COIN;
    } else if(nHeight < 7430400) {  
        nSubsidy = 3.59178082   * COIN;
    } else if(nHeight < 7459200) {  
        nSubsidy = 3.58630137   * COIN;
    } else if(nHeight < 7488000) {  
        nSubsidy = 3.58082192   * COIN;
    } else if(nHeight < 7516800) {  
        nSubsidy = 3.57534247   * COIN;
    } else if(nHeight < 7545600) {  
        nSubsidy = 3.56986301   * COIN;
    } else if(nHeight < 7574400) {  
        nSubsidy = 3.56438356   * COIN;
    } else if(nHeight < 7603200) {  
        nSubsidy = 3.55890411   * COIN;
    } else if(nHeight < 7632000) {  
        nSubsidy = 3.55342466   * COIN;
    } else if(nHeight < 7660800) {  
        nSubsidy = 3.54794521   * COIN;
    } else if(nHeight < 7689600) {  
        nSubsidy = 3.54246575   * COIN;
    } else if(nHeight < 7718400) {  
        nSubsidy = 3.53698630   * COIN;
    } else if(nHeight < 7747200) {  
        nSubsidy = 3.53150685   * COIN;
    } else if(nHeight < 7776000) {  
        nSubsidy = 3.52602740   * COIN;
    } else if(nHeight < 7804800) {  
        nSubsidy = 3.52054795   * COIN;
    } else if(nHeight < 7833600) {  
        nSubsidy = 3.51506849   * COIN;
    } else if(nHeight < 7862400) {  
        nSubsidy = 3.50958904   * COIN;
    } else if(nHeight < 7891200) {  
        nSubsidy = 3.50410959   * COIN;
    } else if(nHeight < 7920000) {  
        nSubsidy = 3.49863014   * COIN;
    } else if(nHeight < 7948800) {  
        nSubsidy = 3.49315068   * COIN;
    } else if(nHeight < 7977600) {  
        nSubsidy = 3.48767123   * COIN;
    } else if(nHeight < 8006400) {  
        nSubsidy = 3.48219178   * COIN;
    } else if(nHeight < 8035200) {  
        nSubsidy = 3.47671233   * COIN;
    } else if(nHeight < 8064000) {  
        nSubsidy = 3.47123288   * COIN;
    } else if(nHeight < 8092800) {  
        nSubsidy = 3.46575342   * COIN;
    } else if(nHeight < 8121600) {  
        nSubsidy = 3.46027397   * COIN;
    } else if(nHeight < 8150400) {  
        nSubsidy = 3.45479452   * COIN;
    } else if(nHeight < 8179200) {  
        nSubsidy = 3.44931507   * COIN;
    } else if(nHeight < 8208000) {  
        nSubsidy = 3.44383562   * COIN;
    } else if(nHeight < 8236800) {  
        nSubsidy = 3.43835616   * COIN;
    } else if(nHeight < 8265600) {  
        nSubsidy = 3.43287671   * COIN;
    } else if(nHeight < 8294400) {  
        nSubsidy = 3.42739726   * COIN;
    } else if(nHeight < 8323200) {  
        nSubsidy = 3.42191781   * COIN;
    } else if(nHeight < 8352000) {  
        nSubsidy = 3.41643836   * COIN;
    } else if(nHeight < 8380800) {  
        nSubsidy = 3.41095890   * COIN;
    } else if(nHeight < 8409600) {  
        nSubsidy = 3.40547945   * COIN;
    } else if(nHeight < 8438400) {  
        nSubsidy = 3.40000000   * COIN;
    } else if(nHeight < 8467200) {  
        nSubsidy = 3.39452055   * COIN;
    } else if(nHeight < 8496000) {  
        nSubsidy = 3.38904110   * COIN;
    } else if(nHeight < 8524800) {  
        nSubsidy = 3.38356164   * COIN;
    } else if(nHeight < 8553600) {  
        nSubsidy = 3.37808219   * COIN;
    } else if(nHeight < 8582400) {  
        nSubsidy = 3.37260274   * COIN;
    } else if(nHeight < 8611200) {  
        nSubsidy = 3.36712329   * COIN;
    } else if(nHeight < 8640000) {  
        nSubsidy = 3.36164384   * COIN;
    } else if(nHeight < 8668800) {  
        nSubsidy = 3.35616438   * COIN;
    } else if(nHeight < 8697600) {  
        nSubsidy = 3.35068493   * COIN;
    } else if(nHeight < 8726400) {  
        nSubsidy = 3.34520548   * COIN;
    } else if(nHeight < 8755200) {  
        nSubsidy = 3.33972603   * COIN;
    } else if(nHeight < 8784000) {  
        nSubsidy = 3.33424658   * COIN;
    } else if(nHeight < 8812800) {  
        nSubsidy = 3.32876712   * COIN;
    } else if(nHeight < 8841600) {  
        nSubsidy = 3.32328767   * COIN;
    } else if(nHeight < 8870400) {  
        nSubsidy = 3.31780822   * COIN;
    } else if(nHeight < 8899200) {  
        nSubsidy = 3.31232877   * COIN;
    } else if(nHeight < 8928000) {  
        nSubsidy = 3.30684932   * COIN;
    } else if(nHeight < 8956800) {  
        nSubsidy = 3.30136986   * COIN;
    } else if(nHeight < 8985600) {  
        nSubsidy = 3.29589041   * COIN;
    } else if(nHeight < 9014400) {  
        nSubsidy = 3.29041096   * COIN;
    } else if(nHeight < 9043200) {  
        nSubsidy = 3.28493151   * COIN;
    } else if(nHeight < 9072000) {  
        nSubsidy = 3.27945205   * COIN;
    } else if(nHeight < 9100800) {  
        nSubsidy = 3.27397260   * COIN;
    } else if(nHeight < 9129600) {  
        nSubsidy = 3.26849315   * COIN;
    } else if(nHeight < 9158400) {  
        nSubsidy = 3.26301370   * COIN;
    } else if(nHeight < 9187200) {  
        nSubsidy = 3.25753425   * COIN;
    } else if(nHeight < 9216000) {  
        nSubsidy = 3.25205479   * COIN;
    } else if(nHeight < 9244800) {  
        nSubsidy = 3.24657534   * COIN;
    } else if(nHeight < 9273600) {  
        nSubsidy = 3.24109589   * COIN;
    } else if(nHeight < 9302400) {  
        nSubsidy = 3.23561644   * COIN;
    } else if(nHeight < 9331200) {  
        nSubsidy = 3.23013699   * COIN;
    } else if(nHeight < 9360000) {  
        nSubsidy = 3.22465753   * COIN;
    } else if(nHeight < 9388800) {  
        nSubsidy = 3.21917808   * COIN;
    } else if(nHeight < 9417600) {  
        nSubsidy = 3.21369863   * COIN;
    } else if(nHeight < 9446400) {  
        nSubsidy = 3.20821918   * COIN;
    } else if(nHeight < 9475200) {  
        nSubsidy = 3.20273973   * COIN;
    } else if(nHeight < 9504000) {  
        nSubsidy = 3.19726027   * COIN;
    } else if(nHeight < 9532800) {  
        nSubsidy = 3.19178082   * COIN;
    } else if(nHeight < 9561600) {  
        nSubsidy = 3.18630137   * COIN;
    } else if(nHeight < 9590400) {  
        nSubsidy = 3.18082192   * COIN;
    } else if(nHeight < 9619200) {  
        nSubsidy = 3.17534247   * COIN;
    } else if(nHeight < 9648000) {  
        nSubsidy = 3.16986301   * COIN;
    } else if(nHeight < 9676800) {  
        nSubsidy = 3.16438356   * COIN;
    } else if(nHeight < 9705600) {  
        nSubsidy = 3.15890411   * COIN;
    } else if(nHeight < 9734400) {  
        nSubsidy = 3.15342466   * COIN;
    } else if(nHeight < 9763200) {  
        nSubsidy = 3.14794521   * COIN;
    } else if(nHeight < 9792000) {  
        nSubsidy = 3.14246575   * COIN;
    } else if(nHeight < 9820800) {  
        nSubsidy = 3.13698630   * COIN;
    } else if(nHeight < 9849600) {  
        nSubsidy = 3.13150685   * COIN;
    } else if(nHeight < 9878400) {  
        nSubsidy = 3.12602740   * COIN;
    } else if(nHeight < 9907200) {  
        nSubsidy = 3.12054795   * COIN;
    } else if(nHeight < 9936000) {  
        nSubsidy = 3.11506849   * COIN;
    } else if(nHeight < 9964800) {  
        nSubsidy = 3.10958904   * COIN;
    } else if(nHeight < 9993600) {  
        nSubsidy = 3.10410959   * COIN;
    } else if(nHeight < 10022400) {  
        nSubsidy = 3.09863014   * COIN;
    } else if(nHeight < 10051200) {  
        nSubsidy = 3.09315068   * COIN;
    } else if(nHeight < 10080000) {  
        nSubsidy = 3.08767123   * COIN;
    } else if(nHeight < 10108800) {  
        nSubsidy = 3.08219178   * COIN;
    } else if(nHeight < 10137600) {  
        nSubsidy = 3.07671233   * COIN;
    } else if(nHeight < 10166400) {  
        nSubsidy = 3.07123288   * COIN;
    } else if(nHeight < 10195200) {  
        nSubsidy = 3.06575342   * COIN;
    } else if(nHeight < 10224000) {  
        nSubsidy = 3.06027397   * COIN;
    } else if(nHeight < 10252800) {  
        nSubsidy = 3.05479452   * COIN;
    } else if(nHeight < 10281600) {  
        nSubsidy = 3.04931507   * COIN;
    } else if(nHeight < 10310400) {  
        nSubsidy = 3.04383562   * COIN;
    } else if(nHeight < 10339200) {  
        nSubsidy = 3.03835616   * COIN;
    } else if(nHeight < 10368000) {  
        nSubsidy = 3.03287671   * COIN;
    } else if(nHeight < 10396800) {  
        nSubsidy = 3.02739726   * COIN;
    } else if(nHeight < 10425600) {  
        nSubsidy = 3.02191781   * COIN;
    } else if(nHeight < 10454400) {  
        nSubsidy = 3.01643836   * COIN;
    } else if(nHeight < 10483200) {  
        nSubsidy = 3.01095890   * COIN;
    } else if(nHeight < 10512000) {  
        nSubsidy = 3.00547945   * COIN;
    } else if(nHeight < 10540800) {  
        nSubsidy = 3.00000000   * COIN;
    } else if(nHeight < 10569600) {  
        nSubsidy = 2.99452055   * COIN;
    } else if(nHeight < 10598400) {  
        nSubsidy = 2.98904110   * COIN;
    } else if(nHeight < 10627200) {  
        nSubsidy = 2.98356164   * COIN;
    } else if(nHeight < 10656000) {  
        nSubsidy = 2.97808219   * COIN;
    } else if(nHeight < 10684800) {  
        nSubsidy = 2.97260274   * COIN;
    } else if(nHeight < 10713600) {  
        nSubsidy = 2.96712329   * COIN;
    } else if(nHeight < 10742400) {  
        nSubsidy = 2.96164384   * COIN;
    } else if(nHeight < 10771200) {  
        nSubsidy = 2.95616438   * COIN;
    } else if(nHeight < 10800000) {  
        nSubsidy = 2.95068493   * COIN;
    } else if(nHeight < 10828800) {  
        nSubsidy = 2.94520548   * COIN;
    } else if(nHeight < 10857600) {  
        nSubsidy = 2.93972603   * COIN;
    } else if(nHeight < 10886400) {  
        nSubsidy = 2.93424658   * COIN;
    } else if(nHeight < 10915200) {  
        nSubsidy = 2.92876712   * COIN;
    } else if(nHeight < 10944000) {  
        nSubsidy = 2.92328767   * COIN;
    } else if(nHeight < 10972800) {  
        nSubsidy = 2.91780822   * COIN;
    } else if(nHeight < 11001600) {  
        nSubsidy = 2.91232877   * COIN;
    } else if(nHeight < 11030400) {  
        nSubsidy = 2.90684932   * COIN;
    } else if(nHeight < 11059200) {  
        nSubsidy = 2.90136986   * COIN;
    } else if(nHeight < 11088000) {  
        nSubsidy = 2.89589041   * COIN;
    } else if(nHeight < 11116800) {  
        nSubsidy = 2.89041096   * COIN;
    } else if(nHeight < 11145600) {  
        nSubsidy = 2.88493151   * COIN;
    } else if(nHeight < 11174400) {  
        nSubsidy = 2.87945205   * COIN;
    } else if(nHeight < 11203200) {  
        nSubsidy = 2.87397260   * COIN;
    } else if(nHeight < 11232000) {  
        nSubsidy = 2.86849315   * COIN;
    } else if(nHeight < 11260800) {  
        nSubsidy = 2.86301370   * COIN;
    } else if(nHeight < 11289600) {  
        nSubsidy = 2.85753425   * COIN;
    } else if(nHeight < 11318400) {  
        nSubsidy = 2.85205479   * COIN;
    } else if(nHeight < 11347200) {  
        nSubsidy = 2.84657534   * COIN;
    } else if(nHeight < 11376000) {  
        nSubsidy = 2.84109589   * COIN;
    } else if(nHeight < 11404800) {  
        nSubsidy = 2.83561644   * COIN;
    } else if(nHeight < 11433600) {  
        nSubsidy = 2.83013699   * COIN;
    } else if(nHeight < 11462400) {  
        nSubsidy = 2.82465753   * COIN;
    } else if(nHeight < 11491200) {  
        nSubsidy = 2.81917808   * COIN;
    } else if(nHeight < 11520000) {  
        nSubsidy = 2.81369863   * COIN;
    } else if(nHeight < 11548800) {  
        nSubsidy = 2.80821918   * COIN;
    } else if(nHeight < 11577600) {  
        nSubsidy = 2.80273973   * COIN;
    } else if(nHeight < 11606400) {  
        nSubsidy = 2.79726027   * COIN;
    } else if(nHeight < 11635200) {  
        nSubsidy = 2.79178082   * COIN;
    } else if(nHeight < 11664000) {  
        nSubsidy = 2.78630137   * COIN;
    } else if(nHeight < 11692800) {  
        nSubsidy = 2.78082192   * COIN;
    } else if(nHeight < 11721600) {  
        nSubsidy = 2.77534247   * COIN;
    } else if(nHeight < 11750400) {  
        nSubsidy = 2.76986301   * COIN;
    } else if(nHeight < 11779200) {  
        nSubsidy = 2.76438356   * COIN;
    } else if(nHeight < 11808000) {  
        nSubsidy = 2.75890411   * COIN;
    } else if(nHeight < 11836800) {  
        nSubsidy = 2.75342466   * COIN;
    } else if(nHeight < 11865600) {  
        nSubsidy = 2.74794521   * COIN;
    } else if(nHeight < 11894400) {  
        nSubsidy = 2.74246575   * COIN;
    } else if(nHeight < 11923200) {  
        nSubsidy = 2.73698630   * COIN;
    } else if(nHeight < 11952000) {  
        nSubsidy = 2.73150685   * COIN;
    } else if(nHeight < 11980800) {  
        nSubsidy = 2.72602740   * COIN;
    } else if(nHeight < 12009600) {  
        nSubsidy = 2.72054795   * COIN;
    } else if(nHeight < 12038400) {  
        nSubsidy = 2.71506849   * COIN;
    } else if(nHeight < 12067200) {  
        nSubsidy = 2.70958904   * COIN;
    } else if(nHeight < 12096000) {  
        nSubsidy = 2.70410959   * COIN;
    } else if(nHeight < 12124800) {  
        nSubsidy = 2.69863014   * COIN;
    } else if(nHeight < 12153600) {  
        nSubsidy = 2.69315068   * COIN;
    } else if(nHeight < 12182400) {  
        nSubsidy = 2.68767123   * COIN;
    } else if(nHeight < 12211200) {  
        nSubsidy = 2.68219178   * COIN;
    } else if(nHeight < 12240000) {  
        nSubsidy = 2.67671233   * COIN;
    } else if(nHeight < 12268800) {  
        nSubsidy = 2.67123288   * COIN;
    } else if(nHeight < 12297600) {  
        nSubsidy = 2.66575342   * COIN;
    } else if(nHeight < 12326400) {  
        nSubsidy = 2.66027397   * COIN;
    } else if(nHeight < 12355200) {  
        nSubsidy = 2.65479452   * COIN;
    } else if(nHeight < 12384000) {  
        nSubsidy = 2.64931507   * COIN;
    } else if(nHeight < 12412800) {  
        nSubsidy = 2.64383562   * COIN;
    } else if(nHeight < 12441600) {  
        nSubsidy = 2.63835616   * COIN;
    } else if(nHeight < 12470400) {  
        nSubsidy = 2.63287671   * COIN;
    } else if(nHeight < 12499200) {  
        nSubsidy = 2.62739726   * COIN;
    } else if(nHeight < 12528000) {  
        nSubsidy = 2.62191781   * COIN;
    } else if(nHeight < 12556800) {  
        nSubsidy = 2.61643836   * COIN;
    } else if(nHeight < 12585600) {  
        nSubsidy = 2.61095890   * COIN;
    } else if(nHeight < 12614400) {  
        nSubsidy = 2.60547945   * COIN;
    } else if(nHeight < 12643200) {  
        nSubsidy = 2.60000000   * COIN;
    } else if(nHeight < 12672000) {  
        nSubsidy = 2.59452055   * COIN;
    } else if(nHeight < 12700800) {  
        nSubsidy = 2.58904110   * COIN;
    } else if(nHeight < 12729600) {  
        nSubsidy = 2.58356164   * COIN;
    } else if(nHeight < 12758400) {  
        nSubsidy = 2.57808219   * COIN;
    } else if(nHeight < 12787200) {  
        nSubsidy = 2.57260274   * COIN;
    } else if(nHeight < 12816000) {  
        nSubsidy = 2.56712329   * COIN;
    } else if(nHeight < 12844800) {  
        nSubsidy = 2.56164384   * COIN;
    } else if(nHeight < 12873600) {  
        nSubsidy = 2.55616438   * COIN;
    } else if(nHeight < 12902400) {  
        nSubsidy = 2.55068493   * COIN;
    } else if(nHeight < 12931200) {  
        nSubsidy = 2.54520548   * COIN;
    } else if(nHeight < 12960000) {  
        nSubsidy = 2.53972603   * COIN;
    } else if(nHeight < 12988800) {  
        nSubsidy = 2.53424658   * COIN;
    } else if(nHeight < 13017600) {  
        nSubsidy = 2.52876712   * COIN;
    } else if(nHeight < 13046400) {  
        nSubsidy = 2.52328767   * COIN;
    } else if(nHeight < 13075200) {  
        nSubsidy = 2.51780822   * COIN;
    } else if(nHeight < 13104000) {  
        nSubsidy = 2.51232877   * COIN;
    } else if(nHeight < 13132800) {  
        nSubsidy = 2.50684932   * COIN;
    } else if(nHeight < 13161600) {  
        nSubsidy = 2.50136986   * COIN;
    } else if(nHeight < 13190400) {  
        nSubsidy = 2.49589041   * COIN;
    } else if(nHeight < 13219200) {  
        nSubsidy = 2.49041096   * COIN;
    } else if(nHeight < 13248000) {  
        nSubsidy = 2.48493151   * COIN;
    } else if(nHeight < 13276800) {  
        nSubsidy = 2.47945205   * COIN;
    } else if(nHeight < 13305600) {  
        nSubsidy = 2.47397260   * COIN;
    } else if(nHeight < 13334400) {  
        nSubsidy = 2.46849315   * COIN;
    } else if(nHeight < 13363200) {  
        nSubsidy = 2.46301370   * COIN;
    } else if(nHeight < 13392000) {  
        nSubsidy = 2.45753425   * COIN;
    } else if(nHeight < 13420800) {  
        nSubsidy = 2.45205479   * COIN;
    } else if(nHeight < 13449600) {  
        nSubsidy = 2.44657534   * COIN;
    } else if(nHeight < 13478400) {  
        nSubsidy = 2.44109589   * COIN;
    } else if(nHeight < 13507200) {  
        nSubsidy = 2.43561644   * COIN;
    } else if(nHeight < 13536000) {  
        nSubsidy = 2.43013699   * COIN;
    } else if(nHeight < 13564800) {  
        nSubsidy = 2.42465753   * COIN;
    } else if(nHeight < 13593600) {  
        nSubsidy = 2.41917808   * COIN;
    } else if(nHeight < 13622400) {  
        nSubsidy = 2.41369863   * COIN;
    } else if(nHeight < 13651200) {  
        nSubsidy = 2.40821918   * COIN;
    } else if(nHeight < 13680000) {  
        nSubsidy = 2.40273973   * COIN;
    } else if(nHeight < 13708800) {  
        nSubsidy = 2.39726027   * COIN;
    } else if(nHeight < 13737600) {  
        nSubsidy = 2.39178082   * COIN;
    } else if(nHeight < 13766400) {  
        nSubsidy = 2.38630137   * COIN;
    } else if(nHeight < 13795200) {  
        nSubsidy = 2.38082192   * COIN;
    } else if(nHeight < 13824000) {  
        nSubsidy = 2.37534247   * COIN;
    } else if(nHeight < 13852800) {  
        nSubsidy = 2.36986301   * COIN;
    } else if(nHeight < 13881600) {  
        nSubsidy = 2.36438356   * COIN;
    } else if(nHeight < 13910400) {  
        nSubsidy = 2.35890411   * COIN;
    } else if(nHeight < 13939200) {  
        nSubsidy = 2.35342466   * COIN;
    } else if(nHeight < 13968000) {  
        nSubsidy = 2.34794521   * COIN;
    } else if(nHeight < 13996800) {  
        nSubsidy = 2.34246575   * COIN;
    } else if(nHeight < 14025600) {  
        nSubsidy = 2.33698630   * COIN;
    } else if(nHeight < 14054400) {  
        nSubsidy = 2.33150685   * COIN;
    } else if(nHeight < 14083200) {  
        nSubsidy = 2.32602740   * COIN;
    } else if(nHeight < 14112000) {  
        nSubsidy = 2.32054795   * COIN;
    } else if(nHeight < 14140800) {  
        nSubsidy = 2.31506849   * COIN;
    } else if(nHeight < 14169600) {  
        nSubsidy = 2.30958904   * COIN;
    } else if(nHeight < 14198400) {  
        nSubsidy = 2.30410959   * COIN;
    } else if(nHeight < 14227200) {  
        nSubsidy = 2.29863014   * COIN;
    } else if(nHeight < 14256000) {  
        nSubsidy = 2.29315068   * COIN;
    } else if(nHeight < 14284800) {  
        nSubsidy = 2.28767123   * COIN;
    } else if(nHeight < 14313600) {  
        nSubsidy = 2.28219178   * COIN;
    } else if(nHeight < 14342400) {  
        nSubsidy = 2.27671233   * COIN;
    } else if(nHeight < 14371200) {  
        nSubsidy = 2.27123288   * COIN;
    } else if(nHeight < 14400000) {  
        nSubsidy = 2.26575342   * COIN;
    } else if(nHeight < 14428800) {  
        nSubsidy = 2.26027397   * COIN;
    } else if(nHeight < 14457600) {  
        nSubsidy = 2.25479452   * COIN;
    } else if(nHeight < 14486400) {  
        nSubsidy = 2.24931507   * COIN;
    } else if(nHeight < 14515200) {  
        nSubsidy = 2.24383562   * COIN;
    } else if(nHeight < 14544000) {  
        nSubsidy = 2.23835616   * COIN;
    } else if(nHeight < 14572800) {  
        nSubsidy = 2.23287671   * COIN;
    } else if(nHeight < 14601600) {  
        nSubsidy = 2.22739726   * COIN;
    } else if(nHeight < 14630400) {  
        nSubsidy = 2.22191781   * COIN;
    } else if(nHeight < 14659200) {  
        nSubsidy = 2.21643836   * COIN;
    } else if(nHeight < 14688000) {  
        nSubsidy = 2.21095890   * COIN;
    } else if(nHeight < 14716800) {  
        nSubsidy = 2.20547945   * COIN;
    } else if(nHeight < 14745600) {  
        nSubsidy = 2.20000000   * COIN;
    } else if(nHeight < 14774400) {  
        nSubsidy = 2.19452055   * COIN;
    } else if(nHeight < 14803200) {  
        nSubsidy = 2.18904110   * COIN;
    } else if(nHeight < 14832000) {  
        nSubsidy = 2.18356164   * COIN;
    } else if(nHeight < 14860800) {  
        nSubsidy = 2.17808219   * COIN;
    } else if(nHeight < 14889600) {  
        nSubsidy = 2.17260274   * COIN;
    } else if(nHeight < 14918400) {  
        nSubsidy = 2.16712329   * COIN;
    } else if(nHeight < 14947200) {  
        nSubsidy = 2.16164384   * COIN;
    } else if(nHeight < 14976000) {  
        nSubsidy = 2.15616438   * COIN;
    } else if(nHeight < 15004800) {  
        nSubsidy = 2.15068493   * COIN;
    } else if(nHeight < 15033600) {  
        nSubsidy = 2.14520548   * COIN;
    } else if(nHeight < 15062400) {  
        nSubsidy = 2.13972603   * COIN;
    } else if(nHeight < 15091200) {  
        nSubsidy = 2.13424658   * COIN;
    } else if(nHeight < 15120000) {  
        nSubsidy = 2.12876712   * COIN;
    } else if(nHeight < 15148800) {  
        nSubsidy = 2.12328767   * COIN;
    } else if(nHeight < 15177600) {  
        nSubsidy = 2.11780822   * COIN;
    } else if(nHeight < 15206400) {  
        nSubsidy = 2.11232877   * COIN;
    } else if(nHeight < 15235200) {  
        nSubsidy = 2.10684932   * COIN;
    } else if(nHeight < 15264000) {  
        nSubsidy = 2.10136986   * COIN;
    } else if(nHeight < 15292800) {  
        nSubsidy = 2.09589041   * COIN;
    } else if(nHeight < 15321600) {  
        nSubsidy = 2.09041096   * COIN;
    } else if(nHeight < 15350400) {  
        nSubsidy = 2.08493151   * COIN;
    } else if(nHeight < 15379200) {  
        nSubsidy = 2.07945205   * COIN;
    } else if(nHeight < 15408000) {  
        nSubsidy = 2.07397260   * COIN;
    } else if(nHeight < 15436800) {  
        nSubsidy = 2.06849315   * COIN;
    } else if(nHeight < 15465600) {  
        nSubsidy = 2.06301370   * COIN;
    } else if(nHeight < 15494400) {  
        nSubsidy = 2.05753425   * COIN;
    } else if(nHeight < 15523200) {  
        nSubsidy = 2.05205479   * COIN;
    } else if(nHeight < 15552000) {  
        nSubsidy = 2.04657534   * COIN;
    } else if(nHeight < 15580800) {  
        nSubsidy = 2.04109589   * COIN;
    } else if(nHeight < 15609600) {  
        nSubsidy = 2.03561644   * COIN;
    } else if(nHeight < 15638400) {  
        nSubsidy = 2.03013699   * COIN;
    } else if(nHeight < 15667200) {  
        nSubsidy = 2.02465753   * COIN;
    } else if(nHeight < 15696000) {  
        nSubsidy = 2.01917808   * COIN;
    } else if(nHeight < 15724800) {  
        nSubsidy = 2.01369863   * COIN;
    } else if(nHeight < 15753600) {  
        nSubsidy = 2.00821918   * COIN;
    } else if(nHeight < 15782400) {  
        nSubsidy = 2.00273973   * COIN;
    } else if(nHeight < 15811200) {  
        nSubsidy = 1.99726027   * COIN;
    } else if(nHeight < 15840000) {  
        nSubsidy = 1.99178082   * COIN;
    } else if(nHeight < 15868800) {  
        nSubsidy = 1.98630137   * COIN;
    } else if(nHeight < 15897600) {  
        nSubsidy = 1.98082192   * COIN;
    } else if(nHeight < 15926400) {  
        nSubsidy = 1.97534247   * COIN;
    } else if(nHeight < 15955200) {  
        nSubsidy = 1.96986301   * COIN;
    } else if(nHeight < 15984000) {  
        nSubsidy = 1.96438356   * COIN;
    } else if(nHeight < 16012800) { 
        nSubsidy = 1.95890411   * COIN;
    } else if(nHeight < 16041600) {  
        nSubsidy = 1.95342466   * COIN;
    } else if(nHeight < 16070400) {  
        nSubsidy = 1.94794521   * COIN;
    } else if(nHeight < 16099200) {  
        nSubsidy = 1.94246575   * COIN;
    } else if(nHeight < 16128000) {  
        nSubsidy = 1.93698630   * COIN;
    } else if(nHeight < 16156800) {  
        nSubsidy = 1.93150685   * COIN;
    } else if(nHeight < 16185600) {  
        nSubsidy = 1.92602740   * COIN;
    } else if(nHeight < 16214400) {  
        nSubsidy = 1.92054795   * COIN;
    } else if(nHeight < 16243200) {  
        nSubsidy = 1.91506849   * COIN;
    } else if(nHeight < 16272000) {  
        nSubsidy = 1.90958904   * COIN;
    } else if(nHeight < 16300800) {  
        nSubsidy = 1.90410959   * COIN;
    } else if(nHeight < 16329600) {  
        nSubsidy = 1.89863014   * COIN;
    } else if(nHeight < 16358400) {  
        nSubsidy = 1.89315068   * COIN;
    } else if(nHeight < 16387200) {  
        nSubsidy = 1.88767123   * COIN;
    } else if(nHeight < 16416000) {  
        nSubsidy = 1.88219178   * COIN;
    } else if(nHeight < 16444800) {  
        nSubsidy = 1.87671233   * COIN;
    } else if(nHeight < 16473600) {  
        nSubsidy = 1.87123288   * COIN;
    } else if(nHeight < 16502400) {  
        nSubsidy = 1.86575342   * COIN;
    } else if(nHeight < 16531200) {  
        nSubsidy = 1.86027397   * COIN;
    } else if(nHeight < 16560000) {  
        nSubsidy = 1.85479452   * COIN;
    } else if(nHeight < 16588800) {  
        nSubsidy = 1.84931507   * COIN;
    } else if(nHeight < 16617600) {  
        nSubsidy = 1.84383562   * COIN;
    } else if(nHeight < 16646400) {  
        nSubsidy = 1.83835616   * COIN;
    } else if(nHeight < 16675200) {  
        nSubsidy = 1.83287671   * COIN;
    } else if(nHeight < 16704000) {  
        nSubsidy = 1.82739726   * COIN;
    } else if(nHeight < 16732800) {  
        nSubsidy = 1.82191781   * COIN;
    } else if(nHeight < 16761600) {  
        nSubsidy = 1.81643836   * COIN;
    } else if(nHeight < 16790400) {  
        nSubsidy = 1.81095890   * COIN;
    } else if(nHeight < 16819200) {  
        nSubsidy = 1.80547945   * COIN;
    } else if(nHeight < 16848000) {  
        nSubsidy = 1.80000000   * COIN;
    } else if(nHeight < 16876800) {  
        nSubsidy = 1.79452055   * COIN;
    } else if(nHeight < 16905600) {  
        nSubsidy = 1.78904110   * COIN;
    } else if(nHeight < 16934400) {  
        nSubsidy = 1.78356164   * COIN;
    } else if(nHeight < 16963200) {  
        nSubsidy = 1.77808219   * COIN;
    } else if(nHeight < 16992000) {  
        nSubsidy = 1.77260274   * COIN;
    } else if(nHeight < 17020800) {  
        nSubsidy = 1.76712329   * COIN;
    } else if(nHeight < 17049600) {  
        nSubsidy = 1.76164384   * COIN;
    } else if(nHeight < 17078400) {  
        nSubsidy = 1.75616438   * COIN;
    } else if(nHeight < 17107200) {  
        nSubsidy = 1.75068493   * COIN;
    } else if(nHeight < 17136000) {  
        nSubsidy = 1.74520548   * COIN;
    } else if(nHeight < 17164800) {  
        nSubsidy = 1.73972603   * COIN;
    } else if(nHeight < 17193600) {  
        nSubsidy = 1.73424658   * COIN;
    } else if(nHeight < 17222400) {  
        nSubsidy = 1.72876712   * COIN;
    } else if(nHeight < 17251200) {  
        nSubsidy = 1.72328767   * COIN;
    } else if(nHeight < 17280000) {  
        nSubsidy = 1.71780822   * COIN;
    } else if(nHeight < 17308800) {  
        nSubsidy = 1.71232877   * COIN;
    } else if(nHeight < 17337600) {  
        nSubsidy = 1.70684932   * COIN;
    } else if(nHeight < 17366400) {  
        nSubsidy = 1.70136986   * COIN;
    } else if(nHeight < 17395200) {  
        nSubsidy = 1.69589041   * COIN;
    } else if(nHeight < 17424000) {  
        nSubsidy = 1.69041096   * COIN;
    } else if(nHeight < 17452800) {  
        nSubsidy = 1.68493151   * COIN;
    } else if(nHeight < 17481600) {  
        nSubsidy = 1.67945205   * COIN;
    } else if(nHeight < 17510400) {  
        nSubsidy = 1.67397260   * COIN;
    } else if(nHeight < 17539200) {  
        nSubsidy = 1.66849315   * COIN;
    } else if(nHeight < 17568000) {  
        nSubsidy = 1.66301370   * COIN;
    } else if(nHeight < 17596800) {  
        nSubsidy = 1.65753425   * COIN;
    } else if(nHeight < 17625600) {  
        nSubsidy = 1.65205479   * COIN;
    } else if(nHeight < 17654400) {  
        nSubsidy = 1.64657534   * COIN;
    } else if(nHeight < 17683200) {  
        nSubsidy = 1.64109589   * COIN;
    } else if(nHeight < 17712000) {  
        nSubsidy = 1.63561644   * COIN;
    } else if(nHeight < 17740800) {  
        nSubsidy = 1.63013699   * COIN;
    } else if(nHeight < 17769600) {  
        nSubsidy = 1.62465753   * COIN;
    } else if(nHeight < 17798400) {  
        nSubsidy = 1.61917808   * COIN;
    } else if(nHeight < 17827200) {  
        nSubsidy = 1.61369863   * COIN;
    } else if(nHeight < 17856000) {  
        nSubsidy = 1.60821918   * COIN;
    } else if(nHeight < 17884800) {  
        nSubsidy = 1.60273973   * COIN;
    } else if(nHeight < 17913600) {  
        nSubsidy = 1.59726027   * COIN;
    } else if(nHeight < 17942400) {  
        nSubsidy = 1.59178082   * COIN;
    } else if(nHeight < 17971200) {  
        nSubsidy = 1.58630137   * COIN;
    } else if(nHeight < 18000000) {  
        nSubsidy = 1.58082192   * COIN;
    } else if(nHeight < 18028800) {  
        nSubsidy = 1.57534247   * COIN;
    } else if(nHeight < 18057600) {  
        nSubsidy = 1.56986301   * COIN;
    } else if(nHeight < 18086400) {  
        nSubsidy = 1.56438356   * COIN;
    } else if(nHeight < 18115200) {  
        nSubsidy = 1.55890411   * COIN;
    } else if(nHeight < 18144000) {  
        nSubsidy = 1.55342466   * COIN;
    } else if(nHeight < 18172800) {  
        nSubsidy = 1.54794521   * COIN;
    } else if(nHeight < 18201600) {  
        nSubsidy = 1.54246575   * COIN;
    } else if(nHeight < 18230400) {  
        nSubsidy = 1.53698630   * COIN;
    } else if(nHeight < 18259200) {  
        nSubsidy = 1.53150685   * COIN;
    } else if(nHeight < 18288000) {  
        nSubsidy = 1.52602740   * COIN;
    } else if(nHeight < 18316800) {  
        nSubsidy = 1.52054795   * COIN;
    } else if(nHeight < 18345600) {  
        nSubsidy = 1.51506849   * COIN;
    } else if(nHeight < 18374400) {  
        nSubsidy = 1.50958904   * COIN;
    } else if(nHeight < 18403200) {  
        nSubsidy = 1.50410959   * COIN;
    } else if(nHeight < 18432000) {  
        nSubsidy = 1.49863014   * COIN;
    } else if(nHeight < 18460800) {  
        nSubsidy = 1.49315068   * COIN;
    } else if(nHeight < 18489600) {  
        nSubsidy = 1.48767123   * COIN;
    } else if(nHeight < 18518400) {  
        nSubsidy = 1.48219178   * COIN;
    } else if(nHeight < 18547200) {  
        nSubsidy = 1.47671233   * COIN;
    } else if(nHeight < 18576000) {  
        nSubsidy = 1.47123288   * COIN;
    } else if(nHeight < 18604800) {  
        nSubsidy = 1.46575342   * COIN;
    } else if(nHeight < 18633600) {  
        nSubsidy = 1.46027397   * COIN;
    } else if(nHeight < 18662400) {  
        nSubsidy = 1.45479452   * COIN;
    } else if(nHeight < 18691200) {  
        nSubsidy = 1.44931507   * COIN;
    } else if(nHeight < 18720000) {  
        nSubsidy = 1.44383562   * COIN;
    } else if(nHeight < 18748800) {  
        nSubsidy = 1.43835616   * COIN;
    } else if(nHeight < 18777600) {  
        nSubsidy = 1.43287671   * COIN;
    } else if(nHeight < 18806400) {  
        nSubsidy = 1.42739726   * COIN;
    } else if(nHeight < 18835200) {  
        nSubsidy = 1.42191781   * COIN;
    } else if(nHeight < 18864000) {  
        nSubsidy = 1.41643836   * COIN;
    } else if(nHeight < 18892800) {  
        nSubsidy = 1.41095890   * COIN;
    } else if(nHeight < 18921600) {  
        nSubsidy = 1.40547945   * COIN;
    } else if(nHeight < 18950400) {  
        nSubsidy = 1.40000000   * COIN;
    } else if(nHeight < 18979200) {  
        nSubsidy = 1.39452055   * COIN;
    } else if(nHeight < 19008000) {  
        nSubsidy = 1.38904110   * COIN;
    } else if(nHeight < 19036800) {  
        nSubsidy = 1.38356164   * COIN;
    } else if(nHeight < 19065600) {  
        nSubsidy = 1.37808219   * COIN;
    } else if(nHeight < 19094400) {  
        nSubsidy = 1.37260274   * COIN;
    } else if(nHeight < 19123200) {  
        nSubsidy = 1.36712329   * COIN;
    } else if(nHeight < 19152000) {  
        nSubsidy = 1.36164384   * COIN;
    } else if(nHeight < 19180800) {  
        nSubsidy = 1.35616438   * COIN;
    } else if(nHeight < 19209600) {  
        nSubsidy = 1.35068493   * COIN;
    } else if(nHeight < 19238400) {  
        nSubsidy = 1.34520548   * COIN;
    } else if(nHeight < 19267200) {  
        nSubsidy = 1.33972603   * COIN;
    } else if(nHeight < 19296000) {  
        nSubsidy = 1.33424658   * COIN;
    } else if(nHeight < 19324800) {  
        nSubsidy = 1.32876712   * COIN;
    } else if(nHeight < 19353600) {  
        nSubsidy = 1.32328767   * COIN;
    } else if(nHeight < 19382400) {  
        nSubsidy = 1.31780822   * COIN;
    } else if(nHeight < 19411200) {  
        nSubsidy = 1.31232877   * COIN;
    } else if(nHeight < 19440000) {  
        nSubsidy = 1.30684932   * COIN;
    } else if(nHeight < 19468800) {  
        nSubsidy = 1.30136986   * COIN;
    } else if(nHeight < 19497600) {  
        nSubsidy = 1.29589041   * COIN;
    } else if(nHeight < 19526400) {  
        nSubsidy = 1.29041096   * COIN;
    } else if(nHeight < 19555200) {  
        nSubsidy = 1.28493151   * COIN;
    } else if(nHeight < 19584000) {  
        nSubsidy = 1.27945205   * COIN;
    } else if(nHeight < 19612800) {  
        nSubsidy = 1.27397260   * COIN;
    } else if(nHeight < 19641600) {  
        nSubsidy = 1.26849315   * COIN;
    } else if(nHeight < 19670400) {  
        nSubsidy = 1.26301370   * COIN;
    } else if(nHeight < 19699200) {  
        nSubsidy = 1.25753425   * COIN;
    } else if(nHeight < 19728000) {  
        nSubsidy = 1.25205479   * COIN;
    } else if(nHeight < 19756800) {  
        nSubsidy = 1.24657534   * COIN;
    } else if(nHeight < 19785600) {  
        nSubsidy = 1.24109589   * COIN;
    } else if(nHeight < 19814400) {  
        nSubsidy = 1.23561644   * COIN;
    } else if(nHeight < 19843200) {  
        nSubsidy = 1.23013699   * COIN;
    } else if(nHeight < 19872000) {  
        nSubsidy = 1.22465753   * COIN;
    } else if(nHeight < 19900800) {  
        nSubsidy = 1.21917808   * COIN;
    } else if(nHeight < 19929600) {  
        nSubsidy = 1.21369863   * COIN;
    } else if(nHeight < 19958400) {  
        nSubsidy = 1.20821918   * COIN;
    } else if(nHeight < 19987200) {  
        nSubsidy = 1.20273973   * COIN;
    } else if(nHeight < 20016000) {  
        nSubsidy = 1.19726027   * COIN;
    } else if(nHeight < 20044800) {  
        nSubsidy = 1.19178082   * COIN;
    } else if(nHeight < 20073600) {  
        nSubsidy = 1.18630137   * COIN;
    } else if(nHeight < 20102400) {  
        nSubsidy = 1.18082192   * COIN;
    } else if(nHeight < 20131200) {  
        nSubsidy = 1.17534247   * COIN;
    } else if(nHeight < 20160000) {  
        nSubsidy = 1.16986301   * COIN;
    } else if(nHeight < 20188800) {  
        nSubsidy = 1.16438356   * COIN;
    } else if(nHeight < 20217600) {  
        nSubsidy = 1.15890411   * COIN;
    } else if(nHeight < 20246400) {  
        nSubsidy = 1.15342466   * COIN;
    } else if(nHeight < 20275200) {  
        nSubsidy = 1.14794521   * COIN;
    } else if(nHeight < 20304000) {  
        nSubsidy = 1.14246575   * COIN;
    } else if(nHeight < 20332800) {  
        nSubsidy = 1.13698630   * COIN;
    } else if(nHeight < 20361600) {  
        nSubsidy = 1.13150685   * COIN;
    } else if(nHeight < 20390400) {  
        nSubsidy = 1.12602740   * COIN;
    } else if(nHeight < 20419200) {  
        nSubsidy = 1.12054795   * COIN;
    } else if(nHeight < 20448000) {  
        nSubsidy = 1.11506849   * COIN;
    } else if(nHeight < 20476800) {  
        nSubsidy = 1.10958904   * COIN;
    } else if(nHeight < 20505600) {  
        nSubsidy = 1.10410959   * COIN;
    } else if(nHeight < 20534400) {  
        nSubsidy = 1.09863014   * COIN;
    } else if(nHeight < 20563200) {  
        nSubsidy = 1.09315068   * COIN;
    } else if(nHeight < 20592000) {  
        nSubsidy = 1.08767123   * COIN;
    } else if(nHeight < 20620800) {  
        nSubsidy = 1.08219178   * COIN;
    } else if(nHeight < 20649600) {  
        nSubsidy = 1.07671233   * COIN;
    } else if(nHeight < 20678400) {  
        nSubsidy = 1.07123288   * COIN;
    } else if(nHeight < 20707200) {  
        nSubsidy = 1.06575342   * COIN;
    } else if(nHeight < 20736000) {  
        nSubsidy = 1.06027397   * COIN;
    } else if(nHeight < 20764800) {  
        nSubsidy = 1.05479452   * COIN;
    } else if(nHeight < 20793600) {  
        nSubsidy = 1.04931507   * COIN;
    } else if(nHeight < 20822400) {  
        nSubsidy = 1.04383562   * COIN;
    } else if(nHeight < 20851200) {  
        nSubsidy = 1.03835616   * COIN;
    } else if(nHeight < 20880000) {  
        nSubsidy = 1.03287671   * COIN;
    } else if(nHeight < 20908800) {  
        nSubsidy = 1.02739726   * COIN;
    } else if(nHeight < 20937600) {  
        nSubsidy = 1.02191781   * COIN;
    } else if(nHeight < 20966400) {  
        nSubsidy = 1.01643836   * COIN;
    } else if(nHeight < 20995200) {  
        nSubsidy = 1.01095890   * COIN;
    } else if(nHeight < 21024000) {  
        nSubsidy = 1.00547945   * COIN;
    } else if(nHeight < 21052800) {  
        nSubsidy = 1.00000000   * COIN;
    } else if(nHeight < 21081600) {  
        nSubsidy = 0.99452055   * COIN;
    } else if(nHeight < 21110400) {  
        nSubsidy = 0.98904110   * COIN;
    } else if(nHeight < 21139200) {  
        nSubsidy = 0.98356164   * COIN;
    } else if(nHeight < 21168000) {  
        nSubsidy = 0.97808219   * COIN;
    } else if(nHeight < 21196800) {  
        nSubsidy = 0.97260274   * COIN;
    } else if(nHeight < 21225600) {  
        nSubsidy = 0.96712329   * COIN;
    } else if(nHeight < 21254400) {  
        nSubsidy = 0.96164384   * COIN;
    } else if(nHeight < 21283200) {  
        nSubsidy = 0.95616438   * COIN;
    } else if(nHeight < 21312000) {  
        nSubsidy = 0.95068493   * COIN;
    } else if(nHeight < 21340800) {  
        nSubsidy = 0.94520548   * COIN;
    } else if(nHeight < 21369600) {  
        nSubsidy = 0.93972603   * COIN;
    } else if(nHeight < 21398400) {  
        nSubsidy = 0.93424658   * COIN;
    } else if(nHeight < 21427200) {  
        nSubsidy = 0.92876712   * COIN;
    } else if(nHeight < 21456000) {  
        nSubsidy = 0.92328767   * COIN;
    } else if(nHeight < 21484800) {  
        nSubsidy = 0.91780822   * COIN;
    } else if(nHeight < 21513600) {  
        nSubsidy = 0.91232877   * COIN;
    } else if(nHeight < 21542400) {  
        nSubsidy = 0.90684932   * COIN;
    } else if(nHeight < 21571200) {  
        nSubsidy = 0.90136986   * COIN;
    } else if(nHeight < 21600000) {  
        nSubsidy = 0.89589041   * COIN;
    } else if(nHeight < 21628800) {  
        nSubsidy = 0.89041096   * COIN;
    } else if(nHeight < 21657600) {  
        nSubsidy = 0.88493151   * COIN;
    } else if(nHeight < 21686400) {  
        nSubsidy = 0.87945205   * COIN;
    } else if(nHeight < 21715200) {  
        nSubsidy = 0.87397260   * COIN;
    } else if(nHeight < 21744000) {  
        nSubsidy = 0.86849315   * COIN;
    } else if(nHeight < 21772800) {  
        nSubsidy = 0.86301370   * COIN;
    } else if(nHeight < 21801600) {  
        nSubsidy = 0.85753425   * COIN;
    } else if(nHeight < 21830400) {  
        nSubsidy = 0.85205479   * COIN;
    } else if(nHeight < 21859200) {  
        nSubsidy = 0.84657534   * COIN;
    } else if(nHeight < 21888000) {  
        nSubsidy = 0.84109589   * COIN;
    } else if(nHeight < 21916800) {  
        nSubsidy = 0.83561644   * COIN;
    } else if(nHeight < 21945600) {  
        nSubsidy = 0.83013699   * COIN;
    } else if(nHeight < 21974400) {  
        nSubsidy = 0.82465753   * COIN;
    } else if(nHeight < 22003200) {  
        nSubsidy = 0.81917808   * COIN;
    } else if(nHeight < 22032000) {  
        nSubsidy = 0.81369863   * COIN;
    } else if(nHeight < 22060800) {  
        nSubsidy = 0.80821918   * COIN;
    } else if(nHeight < 22089600) {  
        nSubsidy = 0.80273973   * COIN;
    } else if(nHeight < 22118400) {  
        nSubsidy = 0.79726027   * COIN;
    } else if(nHeight < 22147200) {  
        nSubsidy = 0.79178082   * COIN;
    } else if(nHeight < 22176000) {  
        nSubsidy = 0.78630137   * COIN;
    } else if(nHeight < 22204800) {  
        nSubsidy = 0.78082192   * COIN;
    } else if(nHeight < 22233600) {  
        nSubsidy = 0.77534247   * COIN;
    } else if(nHeight < 22262400) {  
        nSubsidy = 0.76986301   * COIN;
    } else if(nHeight < 22291200) {  
        nSubsidy = 0.76438356   * COIN;
    } else if(nHeight < 22320000) {  
        nSubsidy = 0.75890411   * COIN;
    } else if(nHeight < 22348800) {  
        nSubsidy = 0.75342466   * COIN;
    } else if(nHeight < 22377600) {  
        nSubsidy = 0.74794521   * COIN;
    } else if(nHeight < 22406400) {  
        nSubsidy = 0.74246575   * COIN;
    } else if(nHeight < 22435200) {  
        nSubsidy = 0.73698630   * COIN;
    } else if(nHeight < 22464000) {  
        nSubsidy = 0.73150685   * COIN;
    } else if(nHeight < 22492800) {  
        nSubsidy = 0.72602740   * COIN;
    } else if(nHeight < 22521600) {  
        nSubsidy = 0.72054795   * COIN;
    } else if(nHeight < 22550400) {  
        nSubsidy = 0.71506849   * COIN;
    } else if(nHeight < 22579200) {  
        nSubsidy = 0.70958904   * COIN;
    } else if(nHeight < 22608000) {  
        nSubsidy = 0.70410959   * COIN;
    } else if(nHeight < 22636800) {  
        nSubsidy = 0.69863014   * COIN;
    } else if(nHeight < 22665600) {  
        nSubsidy = 0.69315068   * COIN;
    } else if(nHeight < 22694400) {  
        nSubsidy = 0.68767123   * COIN;
    } else if(nHeight < 22723200) {  
        nSubsidy = 0.68219178   * COIN;
    } else if(nHeight < 22752000) {  
        nSubsidy = 0.67671233   * COIN;
    } else if(nHeight < 22780800) {  
        nSubsidy = 0.67123288   * COIN;
    } else if(nHeight < 22809600) {  
        nSubsidy = 0.66575342   * COIN;
    } else if(nHeight < 22838400) {  
        nSubsidy = 0.66027397   * COIN;
    } else if(nHeight < 22867200) {  
        nSubsidy = 0.65479452   * COIN;
    } else if(nHeight < 22896000) {  
        nSubsidy = 0.64931507   * COIN;
    } else if(nHeight < 22924800) {  
        nSubsidy = 0.64383562   * COIN;
    } else if(nHeight < 22953600) {  
        nSubsidy = 0.63835616   * COIN;
    } else if(nHeight < 22982400) {  
        nSubsidy = 0.63287671   * COIN;
    } else if(nHeight < 23011200) {  
        nSubsidy = 0.62739726   * COIN;
    } else if(nHeight < 23040000) {  
        nSubsidy = 0.62191781   * COIN;
    } else if(nHeight < 23068800) {  
        nSubsidy = 0.61643836   * COIN;
    } else if(nHeight < 23097600) {  
        nSubsidy = 0.61095890   * COIN;
    } else if(nHeight < 23126400) {  
        nSubsidy = 0.60547945   * COIN;
    } else if(nHeight < 23155200) {  
        nSubsidy = 0.60000000   * COIN;
    } else if(nHeight < 23184000) {  
        nSubsidy = 0.59452055   * COIN;
    } else if(nHeight < 23212800) {  
        nSubsidy = 0.58904110   * COIN;
    } else if(nHeight < 23241600) {  
        nSubsidy = 0.58356164   * COIN;
    } else if(nHeight < 23270400) {  
        nSubsidy = 0.57808219   * COIN;
    } else if(nHeight < 23299200) {  
        nSubsidy = 0.57260274   * COIN;
    } else if(nHeight < 23328000) {  
        nSubsidy = 0.56712329   * COIN;
    } else if(nHeight < 23356800) {  
        nSubsidy = 0.56164384   * COIN;
    } else if(nHeight < 23385600) {  
        nSubsidy = 0.55616438   * COIN;
    } else if(nHeight < 23414400) {  
        nSubsidy = 0.55068493   * COIN;
    } else if(nHeight < 23443200) {  
        nSubsidy = 0.54520548   * COIN;
    } else if(nHeight < 23472000) {  
        nSubsidy = 0.53972603   * COIN;
    } else if(nHeight < 23500800) {  
        nSubsidy = 0.53424658   * COIN;
    } else if(nHeight < 23529600) {  
        nSubsidy = 0.52876712   * COIN;
    } else if(nHeight < 23558400) {  
        nSubsidy = 0.52328767   * COIN;
    } else if(nHeight < 23587200) {  
        nSubsidy = 0.51780822   * COIN;
    } else if(nHeight < 23616000) {  
        nSubsidy = 0.51232877   * COIN;
    } else if(nHeight < 23644800) {  
        nSubsidy = 0.50684932   * COIN;
    } else if(nHeight < 23673600) {  
        nSubsidy = 0.50136986   * COIN;
    } else if(nHeight < 23702400) {  
        nSubsidy = 0.49589041   * COIN;
    } else if(nHeight < 23731200) {  
        nSubsidy = 0.49041096   * COIN;
    } else if(nHeight < 23760000) {  
        nSubsidy = 0.48493151   * COIN;
    } else if(nHeight < 23788800) {  
        nSubsidy = 0.47945205   * COIN;
    } else if(nHeight < 23817600) {  
        nSubsidy = 0.47397260   * COIN;
    } else if(nHeight < 23846400) {  
        nSubsidy = 0.46849315   * COIN;
    } else if(nHeight < 23875200) {  
        nSubsidy = 0.46301370   * COIN;
    } else if(nHeight < 23904000) {  
        nSubsidy = 0.45753425   * COIN;
    } else if(nHeight < 23932800) {  
        nSubsidy = 0.45205479   * COIN;
    } else if(nHeight < 23961600) {  
        nSubsidy = 0.44657534   * COIN;
    } else if(nHeight < 23990400) {  
        nSubsidy = 0.44109589   * COIN;
    } else if(nHeight < 24019200) {  
        nSubsidy = 0.43561644   * COIN;
    } else if(nHeight < 24048000) {  
        nSubsidy = 0.43013699   * COIN;
    } else if(nHeight < 24076800) {  
        nSubsidy = 0.42465753   * COIN;
    } else if(nHeight < 24105600) {  
        nSubsidy = 0.41917808   * COIN;
    } else if(nHeight < 24134400) {  
        nSubsidy = 0.41369863   * COIN;
    } else if(nHeight < 24163200) {  
        nSubsidy = 0.40821918   * COIN;
    } else if(nHeight < 24192000) {  
        nSubsidy = 0.40273973   * COIN;
    } else if(nHeight < 24220800) {  
        nSubsidy = 0.39726027   * COIN;
    } else if(nHeight < 24249600) {  
        nSubsidy = 0.39178082   * COIN;
    } else if(nHeight < 24278400) {  
        nSubsidy = 0.38630137   * COIN;
    } else if(nHeight < 24307200) {  
        nSubsidy = 0.38082192   * COIN;
    } else if(nHeight < 24336000) {  
        nSubsidy = 0.37534247   * COIN;
    } else if(nHeight < 24364800) {  
        nSubsidy = 0.36986301   * COIN;
    } else if(nHeight < 24393600) {  
        nSubsidy = 0.36438356   * COIN;
    } else if(nHeight < 24422400) {  
        nSubsidy = 0.35890411   * COIN;
    } else if(nHeight < 24451200) {  
        nSubsidy = 0.35342466   * COIN;
    } else if(nHeight < 24480000) {  
        nSubsidy = 0.34794521   * COIN;
    } else if(nHeight < 24508800) {  
        nSubsidy = 0.34246575   * COIN;
    } else if(nHeight < 24537600) {  
        nSubsidy = 0.33698630   * COIN;
    } else if(nHeight < 24566400) {  
        nSubsidy = 0.33150685   * COIN;
    } else if(nHeight < 24595200) {  
        nSubsidy = 0.32602740   * COIN;
    } else if(nHeight < 24624000) {  
        nSubsidy = 0.32054795   * COIN;
    } else if(nHeight < 24652800) {  
        nSubsidy = 0.31506849   * COIN;
    } else if(nHeight < 24681600) {  
        nSubsidy = 0.30958904   * COIN;
    } else if(nHeight < 24710400) {  
        nSubsidy = 0.30410959   * COIN;
    } else if(nHeight < 24739200) {  
        nSubsidy = 0.29863014   * COIN;
    } else if(nHeight < 24768000) {  
        nSubsidy = 0.29315068   * COIN;
    } else if(nHeight < 24796800) {  
        nSubsidy = 0.28767123   * COIN;
    } else if(nHeight < 24825600) {  
        nSubsidy = 0.28219178   * COIN;
    } else if(nHeight < 24854400) {  
        nSubsidy = 0.27671233   * COIN;
    } else if(nHeight < 24883200) {  
        nSubsidy = 0.27123288   * COIN;
    } else if(nHeight < 24912000) {  
        nSubsidy = 0.26575342   * COIN;
    } else if(nHeight < 24940800) {  
        nSubsidy = 0.26027397   * COIN;
    } else if(nHeight < 24969600) {  
        nSubsidy = 0.25479452   * COIN;
    } else if(nHeight < 24998400) {  
        nSubsidy = 0.24931507   * COIN;
    } else if(nHeight < 25027200) {  
        nSubsidy = 0.24383562   * COIN;
    } else if(nHeight < 25056000) {  
        nSubsidy = 0.23835616   * COIN;
    } else if(nHeight < 25084800) {  
        nSubsidy = 0.23287671   * COIN;
    } else if(nHeight < 25113600) {  
        nSubsidy = 0.22739726   * COIN;
    } else if(nHeight < 25142400) {  
        nSubsidy = 0.22191781   * COIN;
    } else if(nHeight < 25171200) {  
        nSubsidy = 0.21643836   * COIN;
    } else if(nHeight < 25200000) {  
        nSubsidy = 0.21095890   * COIN;
    } else if(nHeight < 25228800) {  
        nSubsidy = 0.20547945   * COIN;
    } else if(nHeight < 25257600) {  
        nSubsidy = 0.20000000   * COIN;
    } else if(nHeight < 25286400) {  
        nSubsidy = 0.19452055   * COIN;
    } else if(nHeight < 25315200) {  
        nSubsidy = 0.18904110   * COIN;
    } else if(nHeight < 25344000) {  
        nSubsidy = 0.18356164   * COIN;
    } else if(nHeight < 25372800) {  
        nSubsidy = 0.17808219   * COIN;
    } else if(nHeight < 25401600) {  
        nSubsidy = 0.17260274   * COIN;
    } else if(nHeight < 25430400) {  
        nSubsidy = 0.16712329   * COIN;
    } else if(nHeight < 25459200) {  
        nSubsidy = 0.16164384   * COIN;
    } else if(nHeight < 25488000) {  
        nSubsidy = 0.15616438   * COIN;
    } else if(nHeight < 25516800) {  
        nSubsidy = 0.15068493   * COIN;
    } else if(nHeight < 25545600) {  
        nSubsidy = 0.14520548   * COIN;
    } else if(nHeight < 25574400) {  
        nSubsidy = 0.13972603   * COIN;
    } else if(nHeight < 25603200) {  
        nSubsidy = 0.13424658   * COIN;
    } else if(nHeight < 25632000) {  
        nSubsidy = 0.12876712   * COIN;
    } else if(nHeight < 25660800) {  
        nSubsidy = 0.12328767   * COIN;
    } else if(nHeight < 25689600) {  
        nSubsidy = 0.11780822   * COIN;
    } else if(nHeight < 25718400) {  
        nSubsidy = 0.11232877   * COIN;
    } else if(nHeight < 25747200) {  
        nSubsidy = 0.10684932   * COIN;
    } else if(nHeight < 25776000) {  
        nSubsidy = 0.10136986   * COIN;
    } else if(nHeight < 25804800) {  
        nSubsidy = 0.09589041   * COIN;
    } else if(nHeight < 25833600) {  
        nSubsidy = 0.09041096   * COIN;
    } else if(nHeight < 25862400) {  
        nSubsidy = 0.08493151   * COIN;
    } else if(nHeight < 25891200) {  
        nSubsidy = 0.07945205   * COIN;
    } else if(nHeight < 25920000) {  
        nSubsidy = 0.07397260   * COIN;
    } else if(nHeight < 25948800) {  
        nSubsidy = 0.06849315   * COIN;
    } else if(nHeight < 25977600) {  
        nSubsidy = 0.06301370   * COIN;
    } else if(nHeight < 26006400) {  
        nSubsidy = 0.05753425   * COIN;
    } else if(nHeight < 26035200) {  
        nSubsidy = 0.05205479   * COIN;
    } else if(nHeight < 26064000) {  
        nSubsidy = 0.04657534   * COIN;
    } else if(nHeight < 26092800) {  
        nSubsidy = 0.04109589   * COIN;
    } else if(nHeight < 26121600) {  
        nSubsidy = 0.03561644   * COIN;
    } else if(nHeight < 26150400) {  
        nSubsidy = 0.03013699   * COIN;
    } else if(nHeight < 26179200) {  
        nSubsidy = 0.02465753   * COIN;
    } else if(nHeight < 26208000) {  
        nSubsidy = 0.01917808   * COIN;
    } else if(nHeight < 26236800) {  
        nSubsidy = 0.01369863   * COIN;
    } else if(nHeight < 26265600) {  
        nSubsidy = 0.00821918   * COIN;
    } else if(nHeight < 26294400) {  
        nSubsidy = 0.00273973   * COIN;
    } else if(nHeight >= 26294400) {
         nSubsidy = 0.00001 * COIN; // Not a permanent solution... Will probably change after time.
    }

    // Subsidy is cut in half every 1000 terra blocks, which will occur approximately never
    nSubsidy >>= (nHeight / 1000000000000); // Crypto: In reality, Never. Just forget about this coz it is a dummy value ;) Too lazy to remove this too...

    return nSubsidy + nFees;
}

static const int64 nTargetSpacing = 30; // Crypto: 30 seconds
static const int64 nOriginalInterval = 1; // 1 block = 30 seconds
static const int64 nTargetTimespan = nOriginalInterval * nTargetSpacing;    
static const int64 nInterval = nTargetTimespan / nTargetSpacing;

//
// minimum amount of work that could possibly be required nTime after
// minimum work required was nBase
//
unsigned int ComputeMinWork(unsigned int nBase, int64 nTime)
{
    // Testnet has min-difficulty blocks
    // after nTargetSpacing*2 time between blocks:
    if (fTestNet && nTime > nTargetSpacing*2)
        return bnProofOfWorkLimit.GetCompact();

    CBigNum bnResult;
    bnResult.SetCompact(nBase);
    while (nTime > 0 && bnResult < bnProofOfWorkLimit)
    {
        // Maximum 400% adjustment...
        bnResult *= 4;
        // ... in best-case exactly 4-times-normal target time
        nTime -= nTargetTimespan*4;
    }
    if (bnResult > bnProofOfWorkLimit)
        bnResult = bnProofOfWorkLimit;
    return bnResult.GetCompact();
}
unsigned int static GetNextWorkRequired_Norm(const CBlockIndex* pindexLast, const CBlockHeader *pblock)
{
    unsigned int nProofOfWorkLimit = bnProofOfWorkLimit.GetCompact();

    // Genesis block
    if (pindexLast == NULL)
        return nProofOfWorkLimit;

    // Only change once per interval
    if ((pindexLast->nHeight+1) % nInterval != 0)
    {
        // Special difficulty rule for testnet:
        if (fTestNet)
        {
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->nTime > pindexLast->nTime + nTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % nInterval != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }

        return pindexLast->nBits;
    }

    // Crypto: This fixes an issue where a 51% attack can change difficulty at will.
    // Go back the full period unless it's the first retarget after genesis. Code courtesy of Art Forz
    int blockstogoback = nInterval-1;
    if ((pindexLast->nHeight+1) != nInterval)
        blockstogoback = nInterval;

    // Go back by what we want to be 14 days worth of blocks
    const CBlockIndex* pindexFirst = pindexLast;
    for (int i = 0; pindexFirst && i < blockstogoback; i++)
        pindexFirst = pindexFirst->pprev;
    assert(pindexFirst);

    // Limit adjustment step
    int64 nActualTimespan = pindexLast->GetBlockTime() - pindexFirst->GetBlockTime();
    printf("  nActualTimespan = %"PRI64d"  before bounds\n", nActualTimespan);
    if (nActualTimespan < nTargetTimespan/4)
        nActualTimespan = nTargetTimespan/4;
    if (nActualTimespan > nTargetTimespan*4)
        nActualTimespan = nTargetTimespan*4;

    // Retarget
    CBigNum bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= nTargetTimespan;

    if (bnNew > bnProofOfWorkLimit)
        bnNew = bnProofOfWorkLimit;

    /// debug print
    printf("GetNextWorkRequired RETARGET\n");
    printf("nTargetTimespan = %"PRI64d"    nActualTimespan = %"PRI64d"\n", nTargetTimespan, nActualTimespan);
    printf("Before: %08x  %s\n", pindexLast->nBits, CBigNum().SetCompact(pindexLast->nBits).getuint256().ToString().c_str());
    printf("After:  %08x  %s\n", bnNew.GetCompact(), bnNew.getuint256().ToString().c_str());

    return bnNew.GetCompact();
} 


unsigned int static DarkGravityWave3(const CBlockIndex* pindexLast, const CBlockHeader *pblock) {
    /* current difficulty formula, darkcoin - DarkGravity v3, written by Evan Duffield - evan@darkcoin.io */
    const CBlockIndex *BlockLastSolved = pindexLast;
    const CBlockIndex *BlockReading = pindexLast;
    const CBlockHeader *BlockCreating = pblock;
    BlockCreating = BlockCreating;
    int64 nActualTimespan = 0;
    int64 LastBlockTime = 0;
    int64 PastBlocksMin = 24;
    int64 PastBlocksMax = 24;
    int64 CountBlocks = 0;
    CBigNum PastDifficultyAverage;
    CBigNum PastDifficultyAveragePrev;

    if (BlockLastSolved == NULL || BlockLastSolved->nHeight == 0 || BlockLastSolved->nHeight < PastBlocksMin) { 
        return bnProofOfWorkLimit.GetCompact(); 
    }
        
    for (unsigned int i = 1; BlockReading && BlockReading->nHeight > 0; i++) {
        if (PastBlocksMax > 0 && i > PastBlocksMax) { break; }
        CountBlocks++;

        if(CountBlocks <= PastBlocksMin) {
            if (CountBlocks == 1) { PastDifficultyAverage.SetCompact(BlockReading->nBits); }
            else { PastDifficultyAverage = ((PastDifficultyAveragePrev * CountBlocks)+(CBigNum().SetCompact(BlockReading->nBits))) / (CountBlocks+1); }
            PastDifficultyAveragePrev = PastDifficultyAverage;
        }

        if(LastBlockTime > 0){
            int64 Diff = (LastBlockTime - BlockReading->GetBlockTime());
            nActualTimespan += Diff;
        }
        LastBlockTime = BlockReading->GetBlockTime();      

        if (BlockReading->pprev == NULL) { assert(BlockReading); break; }
        BlockReading = BlockReading->pprev;
    }
    
    CBigNum bnNew(PastDifficultyAverage);

    int64 nTargetTimespan = CountBlocks*nTargetSpacing;

    if (nActualTimespan < nTargetTimespan/3)
        nActualTimespan = nTargetTimespan/3;
    if (nActualTimespan > nTargetTimespan*3)
        nActualTimespan = nTargetTimespan*3;

    // Retarget
    bnNew *= nActualTimespan;
    bnNew /= nTargetTimespan;
    /// debug print
   // printf("DarkGravityWave3 RETARGET\n");
    //printf("nTargetTimespan = %"PRI64d"    nActualTimespan = %"PRI64d"\n", nTargetTimespan, nActualTimespan);
    //printf("Before: %08x  %s\n", pindexLast->nBits, CBigNum().SetCompact(pindexLast->nBits).getuint256().ToString().c_str());
   // printf("After:  %08x  %s\n", bnNew.GetCompact(), bnNew.getuint256().ToString().c_str());

    if (bnNew > bnProofOfWorkLimit){
        bnNew = bnProofOfWorkLimit;
    }
     
    return bnNew.GetCompact();
}

unsigned int static GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock)
{
    
    int DiffMode = 1;
    unsigned int nProofOfWorkLimit = bnProofOfWorkLimit.GetCompact();
    if (fTestNet)
    {
        if (pindexLast->nHeight+1 >= 20) 
            { 
                DiffMode = 2;
            }           
    }
    else
    {
        if (pindexLast->nHeight+1 >= 16) 
            { 
                DiffMode = 2;
            }    
    } 
    if      (DiffMode == 1) { return GetNextWorkRequired_Norm(pindexLast, pblock); }
    else if (DiffMode == 2) { return DarkGravityWave3(pindexLast, pblock); }
    return DarkGravityWave3(pindexLast, pblock);
}


bool CheckProofOfWork(uint256 hash, unsigned int nBits)
{
    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);

    // Check range
    if (bnTarget <= 0 || bnTarget > bnProofOfWorkLimit)
        return error("CheckProofOfWork() : nBits below minimum work");

    // Check proof of work matches claimed amount
    if (hash > bnTarget.getuint256())
        return error("CheckProofOfWork() : hash doesn't match nBits");

    return true;
}

// Return maximum amount of blocks that other nodes claim to have
int GetNumBlocksOfPeers()
{
    return std::max(cPeerBlockCounts.median(), Checkpoints::GetTotalBlocksEstimate());
}

bool IsInitialBlockDownload()
{
    if (pindexBest == NULL || fImporting || fReindex || nBestHeight < Checkpoints::GetTotalBlocksEstimate())
        return true;
    static int64 nLastUpdate;
    static CBlockIndex* pindexLastBest;
    if (pindexBest != pindexLastBest)
    {
        pindexLastBest = pindexBest;
        nLastUpdate = GetTime();
    }
    return (GetTime() - nLastUpdate < 10 &&
            pindexBest->GetBlockTime() < GetTime() - 24 * 60 * 60);
}

void static InvalidChainFound(CBlockIndex* pindexNew)
{
    if (pindexNew->nChainWork > nBestInvalidWork)
    {
        nBestInvalidWork = pindexNew->nChainWork;
        pblocktree->WriteBestInvalidWork(CBigNum(nBestInvalidWork));
        uiInterface.NotifyBlocksChanged();
    }
    printf("InvalidChainFound: invalid block=%s  height=%d  log2_work=%.8g  date=%s\n",
      pindexNew->GetBlockHash().ToString().c_str(), pindexNew->nHeight,
      log(pindexNew->nChainWork.getdouble())/log(2.0), DateTimeStrFormat("%Y-%m-%d %H:%M:%S",
      pindexNew->GetBlockTime()).c_str());
    printf("InvalidChainFound:  current best=%s  height=%d  log2_work=%.8g  date=%s\n",
      hashBestChain.ToString().c_str(), nBestHeight, log(nBestChainWork.getdouble())/log(2.0),
      DateTimeStrFormat("%Y-%m-%d %H:%M:%S", pindexBest->GetBlockTime()).c_str());
    if (pindexBest && nBestInvalidWork > nBestChainWork + (pindexBest->GetBlockWork() * 6).getuint256())
        printf("InvalidChainFound: Warning: Displayed transactions may not be correct! You may need to upgrade, or other nodes may need to upgrade.\n");
}

void static InvalidBlockFound(CBlockIndex *pindex) {
    pindex->nStatus |= BLOCK_FAILED_VALID;
    pblocktree->WriteBlockIndex(CDiskBlockIndex(pindex));
    setBlockIndexValid.erase(pindex);
    InvalidChainFound(pindex);
    if (pindex->pnext) {
        CValidationState stateDummy;
        ConnectBestBlock(stateDummy); // reorganise away from the failed block
    }
}

bool ConnectBestBlock(CValidationState &state) {
    do {
        CBlockIndex *pindexNewBest;

        {
            std::set<CBlockIndex*,CBlockIndexWorkComparator>::reverse_iterator it = setBlockIndexValid.rbegin();
            if (it == setBlockIndexValid.rend())
                return true;
            pindexNewBest = *it;
        }

        if (pindexNewBest == pindexBest || (pindexBest && pindexNewBest->nChainWork == pindexBest->nChainWork))
            return true; // nothing to do

        // check ancestry
        CBlockIndex *pindexTest = pindexNewBest;
        std::vector<CBlockIndex*> vAttach;
        do {
            if (pindexTest->nStatus & BLOCK_FAILED_MASK) {
                // mark descendants failed
                CBlockIndex *pindexFailed = pindexNewBest;
                while (pindexTest != pindexFailed) {
                    pindexFailed->nStatus |= BLOCK_FAILED_CHILD;
                    setBlockIndexValid.erase(pindexFailed);
                    pblocktree->WriteBlockIndex(CDiskBlockIndex(pindexFailed));
                    pindexFailed = pindexFailed->pprev;
                }
                InvalidChainFound(pindexNewBest);
                break;
            }

            if (pindexBest == NULL || pindexTest->nChainWork > pindexBest->nChainWork)
                vAttach.push_back(pindexTest);

            if (pindexTest->pprev == NULL || pindexTest->pnext != NULL) {
                reverse(vAttach.begin(), vAttach.end());
                BOOST_FOREACH(CBlockIndex *pindexSwitch, vAttach) {
                    boost::this_thread::interruption_point();
                    try {
                        if (!SetBestChain(state, pindexSwitch))
                            return false;
                    } catch(std::runtime_error &e) {
                        return state.Abort(_("System error: ") + e.what());
                    }
                }
                return true;
            }
            pindexTest = pindexTest->pprev;
        } while(true);
    } while(true);
}

void CBlockHeader::UpdateTime(const CBlockIndex* pindexPrev)
{
    nTime = max(pindexPrev->GetMedianTimePast()+1, GetAdjustedTime());
    LastHeight = pindexPrev->nHeight;

    // Updating time can change work required on testnet:
    if (fTestNet)
        nBits = GetNextWorkRequired(pindexPrev, this);
}





const CTxOut &CTransaction::GetOutputFor(const CTxIn& input, CCoinsViewCache& view)
{
    const CCoins &coins = view.GetCoins(input.prevout.hash);
    assert(coins.IsAvailable(input.prevout.n));
    return coins.vout[input.prevout.n];
}

int64 CTransaction::GetValueIn(CCoinsViewCache& inputs) const
{
    if (IsCoinBase())
        return 0;

    int64 nResult = 0;
    for (unsigned int i = 0; i < vin.size(); i++)
        nResult += GetOutputFor(vin[i], inputs).nValue;

    return nResult;
}

unsigned int CTransaction::GetP2SHSigOpCount(CCoinsViewCache& inputs) const
{
    if (IsCoinBase())
        return 0;

    unsigned int nSigOps = 0;
    for (unsigned int i = 0; i < vin.size(); i++)
    {
        const CTxOut &prevout = GetOutputFor(vin[i], inputs);
        if (prevout.scriptPubKey.IsPayToScriptHash())
            nSigOps += prevout.scriptPubKey.GetSigOpCount(vin[i].scriptSig);
    }
    return nSigOps;
}

void CTransaction::UpdateCoins(CValidationState &state, CCoinsViewCache &inputs, CTxUndo &txundo, int nHeight, const uint256 &txhash) const
{
    bool ret;
    // mark inputs spent
    if (!IsCoinBase()) {
        BOOST_FOREACH(const CTxIn &txin, vin) {
            CCoins &coins = inputs.GetCoins(txin.prevout.hash);
            CTxInUndo undo;
            ret = coins.Spend(txin.prevout, undo);
            assert(ret);
            txundo.vprevout.push_back(undo);
        }
    }

    // add outputs
    assert(inputs.SetCoins(txhash, CCoins(*this, nHeight)));
}

bool CTransaction::HaveInputs(CCoinsViewCache &inputs) const
{
    if (!IsCoinBase()) {
        // first check whether information about the prevout hash is available
        for (unsigned int i = 0; i < vin.size(); i++) {
            const COutPoint &prevout = vin[i].prevout;
            if (!inputs.HaveCoins(prevout.hash))
                return false;
        }

        // then check whether the actual outputs are available
        for (unsigned int i = 0; i < vin.size(); i++) {
            const COutPoint &prevout = vin[i].prevout;
            const CCoins &coins = inputs.GetCoins(prevout.hash);
            if (!coins.IsAvailable(prevout.n))
                return false;
        }
    }
    return true;
}

bool CScriptCheck::operator()() const {
    const CScript &scriptSig = ptxTo->vin[nIn].scriptSig;
    if (!VerifyScript(scriptSig, scriptPubKey, *ptxTo, nIn, nFlags, nHashType))
        return error("CScriptCheck() : %s VerifySignature failed", ptxTo->GetHash().ToString().c_str());
    return true;
}

bool VerifySignature(const CCoins& txFrom, const CTransaction& txTo, unsigned int nIn, unsigned int flags, int nHashType)
{
    return CScriptCheck(txFrom, txTo, nIn, flags, nHashType)();
}

bool CTransaction::CheckInputs(CValidationState &state, CCoinsViewCache &inputs, bool fScriptChecks, unsigned int flags, std::vector<CScriptCheck> *pvChecks) const
{
    if (!IsCoinBase())
    {
        if (pvChecks)
            pvChecks->reserve(vin.size());

        // This doesn't trigger the DoS code on purpose; if it did, it would make it easier
        // for an attacker to attempt to split the network.
        if (!HaveInputs(inputs))
            return state.Invalid(error("CheckInputs() : %s inputs unavailable", GetHash().ToString().c_str()));

        // While checking, GetBestBlock() refers to the parent block.
        // This is also true for mempool checks.
        int nSpendHeight = inputs.GetBestBlock()->nHeight + 1;
        int64 nValueIn = 0;
        int64 nFees = 0;
        for (unsigned int i = 0; i < vin.size(); i++)
        {
            const COutPoint &prevout = vin[i].prevout;
            const CCoins &coins = inputs.GetCoins(prevout.hash);

            // If prev is coinbase, check that it's matured
            if (coins.IsCoinBase()) {
                if (nSpendHeight - coins.nHeight < COINBASE_MATURITY)
                    return state.Invalid(error("CheckInputs() : tried to spend coinbase at depth %d", nSpendHeight - coins.nHeight));
            }

            // Check for negative or overflow input values
            nValueIn += coins.vout[prevout.n].nValue;
            if (!MoneyRange(coins.vout[prevout.n].nValue) || !MoneyRange(nValueIn))
                return state.DoS(100, error("CheckInputs() : txin values out of range"));

        }

        if (nValueIn < GetValueOut())
            return state.DoS(100, error("CheckInputs() : %s value in < value out", GetHash().ToString().c_str()));

        // Tally transaction fees
        int64 nTxFee = nValueIn - GetValueOut();
        if (nTxFee < 0)
            return state.DoS(100, error("CheckInputs() : %s nTxFee < 0", GetHash().ToString().c_str()));
        nFees += nTxFee;
        if (!MoneyRange(nFees))
            return state.DoS(100, error("CheckInputs() : nFees out of range"));

        // The first loop above does all the inexpensive checks.
        // Only if ALL inputs pass do we perform expensive ECDSA signature checks.
        // Helps prevent CPU exhaustion attacks.

        // Skip ECDSA signature verification when connecting blocks
        // before the last block chain checkpoint. This is safe because block merkle hashes are
        // still computed and checked, and any change will be caught at the next checkpoint.
        if (fScriptChecks) {
            for (unsigned int i = 0; i < vin.size(); i++) {
                const COutPoint &prevout = vin[i].prevout;
                const CCoins &coins = inputs.GetCoins(prevout.hash);

                // Verify signature
                CScriptCheck check(coins, *this, i, flags, 0);
                if (pvChecks) {
                    pvChecks->push_back(CScriptCheck());
                    check.swap(pvChecks->back());
                } else if (!check()) {
                    if (flags & SCRIPT_VERIFY_STRICTENC) {
                        // For now, check whether the failure was caused by non-canonical
                        // encodings or not; if so, don't trigger DoS protection.
                        CScriptCheck check(coins, *this, i, flags & (~SCRIPT_VERIFY_STRICTENC), 0);
                        if (check())
                            return state.Invalid();
                    }
                    return state.DoS(100,false);
                }
            }
        }
    }

    return true;
}




bool CBlock::DisconnectBlock(CValidationState &state, CBlockIndex *pindex, CCoinsViewCache &view, bool *pfClean)
{
    assert(pindex == view.GetBestBlock());

    if (pfClean)
        *pfClean = false;

    bool fClean = true;

    CBlockUndo blockUndo;
    CDiskBlockPos pos = pindex->GetUndoPos();
    if (pos.IsNull())
        return error("DisconnectBlock() : no undo data available");
    if (!blockUndo.ReadFromDisk(pos, pindex->pprev->GetBlockHash()))
        return error("DisconnectBlock() : failure reading undo data");

    if (blockUndo.vtxundo.size() + 1 != vtx.size())
        return error("DisconnectBlock() : block and undo data inconsistent");

    // undo transactions in reverse order
    for (int i = vtx.size() - 1; i >= 0; i--) {
        const CTransaction &tx = vtx[i];
        uint256 hash = tx.GetHash();

        // check that all outputs are available
        if (!view.HaveCoins(hash)) {
            fClean = fClean && error("DisconnectBlock() : outputs still spent? database corrupted");
            view.SetCoins(hash, CCoins());
        }
        CCoins &outs = view.GetCoins(hash);

        CCoins outsBlock = CCoins(tx, pindex->nHeight);
        // The CCoins serialization does not serialize negative numbers.
        // No network rules currently depend on the version here, so an inconsistency is harmless
        // but it must be corrected before txout nversion ever influences a network rule.
        if (outsBlock.nVersion < 0)
            outs.nVersion = outsBlock.nVersion;
        if (outs != outsBlock)
            fClean = fClean && error("DisconnectBlock() : added transaction mismatch? database corrupted");

        // remove outputs
        outs = CCoins();

        // restore inputs
        if (i > 0) { // not coinbases
            const CTxUndo &txundo = blockUndo.vtxundo[i-1];
            if (txundo.vprevout.size() != tx.vin.size())
                return error("DisconnectBlock() : transaction and undo data inconsistent");
            for (unsigned int j = tx.vin.size(); j-- > 0;) {
                const COutPoint &out = tx.vin[j].prevout;
                const CTxInUndo &undo = txundo.vprevout[j];
                CCoins coins;
                view.GetCoins(out.hash, coins); // this can fail if the prevout was already entirely spent
                if (undo.nHeight != 0) {
                    // undo data contains height: this is the last output of the prevout tx being spent
                    if (!coins.IsPruned())
                        fClean = fClean && error("DisconnectBlock() : undo data overwriting existing transaction");
                    coins = CCoins();
                    coins.fCoinBase = undo.fCoinBase;
                    coins.nHeight = undo.nHeight;
                    coins.nVersion = undo.nVersion;
                } else {
                    if (coins.IsPruned())
                        fClean = fClean && error("DisconnectBlock() : undo data adding output to missing transaction");
                }
                if (coins.IsAvailable(out.n))
                    fClean = fClean && error("DisconnectBlock() : undo data overwriting existing output");
                if (coins.vout.size() < out.n+1)
                    coins.vout.resize(out.n+1);
                coins.vout[out.n] = undo.txout;
                if (!view.SetCoins(out.hash, coins))
                    return error("DisconnectBlock() : cannot restore coin inputs");
            }
        }
    }

    // move best block pointer to prevout block
    view.SetBestBlock(pindex->pprev);

    if (pfClean) {
        *pfClean = fClean;
        return true;
    } else {
        return fClean;
    }
}

void static FlushBlockFile(bool fFinalize = false)
{
    LOCK(cs_LastBlockFile);

    CDiskBlockPos posOld(nLastBlockFile, 0);

    FILE *fileOld = OpenBlockFile(posOld);
    if (fileOld) {
        if (fFinalize)
            TruncateFile(fileOld, infoLastBlockFile.nSize);
        FileCommit(fileOld);
        fclose(fileOld);
    }

    fileOld = OpenUndoFile(posOld);
    if (fileOld) {
        if (fFinalize)
            TruncateFile(fileOld, infoLastBlockFile.nUndoSize);
        FileCommit(fileOld);
        fclose(fileOld);
    }
}

bool FindUndoPos(CValidationState &state, int nFile, CDiskBlockPos &pos, unsigned int nAddSize);

static CCheckQueue<CScriptCheck> scriptcheckqueue(128);

void ThreadScriptCheck() {
    RenameThread("bitcoin-scriptch");
    scriptcheckqueue.Thread();
}

bool CBlock::ConnectBlock(CValidationState &state, CBlockIndex* pindex, CCoinsViewCache &view, bool fJustCheck)
{
    LastHeight = pindex->nHeight;
    // Check it again in case a previous version let a bad block in
    if (!CheckBlock(state, !fJustCheck, !fJustCheck))
        return false;

    // verify that the view's current state corresponds to the previous block
    assert(pindex->pprev == view.GetBestBlock());

    // Special case for the genesis block, skipping connection of its transactions
    // (its coinbase is unspendable)
    if (GetHash() == hashGenesisBlock) {
        view.SetBestBlock(pindex);
        pindexGenesisBlock = pindex;
        return true;
    }

    bool fScriptChecks = pindex->nHeight >= Checkpoints::GetTotalBlocksEstimate();

    // Do not allow blocks that contain transactions which 'overwrite' older transactions,
    // unless those are already completely spent.
    // If such overwrites are allowed, coinbases and transactions depending upon those
    // can be duplicated to remove the ability to spend the first instance -- even after
    // being sent to another address.
    // See BIP30 and http://r6.ca/blog/20120206T005236Z.html for more information.
    // This logic is not necessary for memory pool transactions, as AcceptToMemoryPool
    // already refuses previously-known transaction ids entirely.
    // This rule was originally applied all blocks whose timestamp was after October 1, 2012, 0:00 UTC.
    // Now that the whole chain is irreversibly beyond that time it is applied to all blocks,
    // this prevents exploiting the issue against nodes in their initial block download.
    bool fEnforceBIP30 = true;

    if (fEnforceBIP30) {
        for (unsigned int i=0; i<vtx.size(); i++) {
            uint256 hash = GetTxHash(i);
            if (view.HaveCoins(hash) && !view.GetCoins(hash).IsPruned())
                return state.DoS(100, error("ConnectBlock() : tried to overwrite transaction"));
        }
    }

    // BIP16 didn't become active until Oct 1 2012
    int64 nBIP16SwitchTime = 1349049600;
    bool fStrictPayToScriptHash = (pindex->nTime >= nBIP16SwitchTime);

    unsigned int flags = SCRIPT_VERIFY_NOCACHE |
                         (fStrictPayToScriptHash ? SCRIPT_VERIFY_P2SH : SCRIPT_VERIFY_NONE);

    CBlockUndo blockundo;

    CCheckQueueControl<CScriptCheck> control(fScriptChecks && nScriptCheckThreads ? &scriptcheckqueue : NULL);

    int64 nStart = GetTimeMicros();
    int64 nFees = 0;
    int nInputs = 0;
    unsigned int nSigOps = 0;
    CDiskTxPos pos(pindex->GetBlockPos(), GetSizeOfCompactSize(vtx.size()));
    std::vector<std::pair<uint256, CDiskTxPos> > vPos;
    vPos.reserve(vtx.size());
    for (unsigned int i=0; i<vtx.size(); i++)
    {
        const CTransaction &tx = vtx[i];

        nInputs += tx.vin.size();
        nSigOps += tx.GetLegacySigOpCount();
        if (nSigOps > MAX_BLOCK_SIGOPS)
            return state.DoS(100, error("ConnectBlock() : too many sigops"));

        if (!tx.IsCoinBase())
        {
            if (!tx.HaveInputs(view))
                return state.DoS(100, error("ConnectBlock() : inputs missing/spent"));

            if (fStrictPayToScriptHash)
            {
                // Add in sigops done by pay-to-script-hash inputs;
                // this is to prevent a "rogue miner" from creating
                // an incredibly-expensive-to-validate block.
                nSigOps += tx.GetP2SHSigOpCount(view);
                if (nSigOps > MAX_BLOCK_SIGOPS)
                     return state.DoS(100, error("ConnectBlock() : too many sigops"));
            }

            nFees += tx.GetValueIn(view)-tx.GetValueOut();

            std::vector<CScriptCheck> vChecks;
            if (!tx.CheckInputs(state, view, fScriptChecks, flags, nScriptCheckThreads ? &vChecks : NULL))
                return false;
            control.Add(vChecks);
        }

        CTxUndo txundo;
        tx.UpdateCoins(state, view, txundo, pindex->nHeight, GetTxHash(i));
        if (!tx.IsCoinBase())
            blockundo.vtxundo.push_back(txundo);

        vPos.push_back(std::make_pair(GetTxHash(i), pos));
        pos.nTxOffset += ::GetSerializeSize(tx, SER_DISK, CLIENT_VERSION);
    }
    int64 nTime = GetTimeMicros() - nStart;
    if (fBenchmark)
        printf("- Connect %u transactions: %.2fms (%.3fms/tx, %.3fms/txin)\n", (unsigned)vtx.size(), 0.001 * nTime, 0.001 * nTime / vtx.size(), nInputs <= 1 ? 0 : 0.001 * nTime / (nInputs-1));

    if (vtx[0].GetValueOut() > GetBlockValue(pindex->nHeight, nFees))
        return state.DoS(100, error("ConnectBlock() : coinbase pays too much (actual=%" PRI64d" vs limit=%" PRI64d")", vtx[0].GetValueOut(), GetBlockValue(pindex->nHeight, nFees)));

    if (!control.Wait())
        return state.DoS(100, false);
    int64 nTime2 = GetTimeMicros() - nStart;
    if (fBenchmark)
        printf("- Verify %u txins: %.2fms (%.3fms/txin)\n", nInputs - 1, 0.001 * nTime2, nInputs <= 1 ? 0 : 0.001 * nTime2 / (nInputs-1));

    if (fJustCheck)
        return true;

    // Write undo information to disk
    if (pindex->GetUndoPos().IsNull() || (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_SCRIPTS)
    {
        if (pindex->GetUndoPos().IsNull()) {
            CDiskBlockPos pos;
            if (!FindUndoPos(state, pindex->nFile, pos, ::GetSerializeSize(blockundo, SER_DISK, CLIENT_VERSION) + 40))
                return error("ConnectBlock() : FindUndoPos failed");
            if (!blockundo.WriteToDisk(pos, pindex->pprev->GetBlockHash()))
                return state.Abort(_("Failed to write undo data"));

            // update nUndoPos in block index
            pindex->nUndoPos = pos.nPos;
            pindex->nStatus |= BLOCK_HAVE_UNDO;
        }

        pindex->nStatus = (pindex->nStatus & ~BLOCK_VALID_MASK) | BLOCK_VALID_SCRIPTS;

        CDiskBlockIndex blockindex(pindex);
        if (!pblocktree->WriteBlockIndex(blockindex))
            return state.Abort(_("Failed to write block index"));
    }

    if (fTxIndex)
        if (!pblocktree->WriteTxIndex(vPos))
            return state.Abort(_("Failed to write transaction index"));

    // add this block to the view's block chain
    assert(view.SetBestBlock(pindex));

    // Watch for transactions paying to me
    for (unsigned int i=0; i<vtx.size(); i++)
        SyncWithWallets(GetTxHash(i), vtx[i], this, true);

    return true;
}

bool SetBestChain(CValidationState &state, CBlockIndex* pindexNew)
{
    // All modifications to the coin state will be done in this cache.
    // Only when all have succeeded, we push it to pcoinsTip.
    CCoinsViewCache view(*pcoinsTip, true);

    // Find the fork (typically, there is none)
    CBlockIndex* pfork = view.GetBestBlock();
    CBlockIndex* plonger = pindexNew;
    while (pfork && pfork != plonger)
    {
        while (plonger->nHeight > pfork->nHeight) {
            plonger = plonger->pprev;
            assert(plonger != NULL);
        }
        if (pfork == plonger)
            break;
        pfork = pfork->pprev;
        assert(pfork != NULL);
    }

    // List of what to disconnect (typically nothing)
    vector<CBlockIndex*> vDisconnect;
    for (CBlockIndex* pindex = view.GetBestBlock(); pindex != pfork; pindex = pindex->pprev)
        vDisconnect.push_back(pindex);

    // List of what to connect (typically only pindexNew)
    vector<CBlockIndex*> vConnect;
    for (CBlockIndex* pindex = pindexNew; pindex != pfork; pindex = pindex->pprev)
        vConnect.push_back(pindex);
    reverse(vConnect.begin(), vConnect.end());

    if (vDisconnect.size() > 0) {
        printf("REORGANIZE: Disconnect %" PRIszu" blocks; %s..\n", vDisconnect.size(), pfork->GetBlockHash().ToString().c_str());
        printf("REORGANIZE: Connect %" PRIszu" blocks; ..%s\n", vConnect.size(), pindexNew->GetBlockHash().ToString().c_str());
    }

    // Disconnect shorter branch
    vector<CTransaction> vResurrect;
    BOOST_FOREACH(CBlockIndex* pindex, vDisconnect) {
        CBlock block;
        if (!block.ReadFromDisk(pindex))
            return state.Abort(_("Failed to read block"));
        int64 nStart = GetTimeMicros();
        if (!block.DisconnectBlock(state, pindex, view))
            return error("SetBestBlock() : DisconnectBlock %s failed", pindex->GetBlockHash().ToString().c_str());
        if (fBenchmark)
            printf("- Disconnect: %.2fms\n", (GetTimeMicros() - nStart) * 0.001);

        // Queue memory transactions to resurrect.
        // We only do this for blocks after the last checkpoint (reorganisation before that
        // point should only happen with -reindex/-loadblock, or a misbehaving peer.
        BOOST_FOREACH(const CTransaction& tx, block.vtx)
            if (!tx.IsCoinBase() && pindex->nHeight > Checkpoints::GetTotalBlocksEstimate())
                vResurrect.push_back(tx);
    }

    // Connect longer branch
    vector<CTransaction> vDelete;
    BOOST_FOREACH(CBlockIndex *pindex, vConnect) {
        CBlock block;
        if (!block.ReadFromDisk(pindex))
            return state.Abort(_("Failed to read block"));
        int64 nStart = GetTimeMicros();
        if (!block.ConnectBlock(state, pindex, view)) {
            if (state.IsInvalid()) {
                InvalidChainFound(pindexNew);
                InvalidBlockFound(pindex);
            }
            return error("SetBestBlock() : ConnectBlock %s failed", pindex->GetBlockHash().ToString().c_str());
        }
        if (fBenchmark)
            printf("- Connect: %.2fms\n", (GetTimeMicros() - nStart) * 0.001);

        // Queue memory transactions to delete
        BOOST_FOREACH(const CTransaction& tx, block.vtx)
            vDelete.push_back(tx);
    }

    // Flush changes to global coin state
    int64 nStart = GetTimeMicros();
    int nModified = view.GetCacheSize();
    assert(view.Flush());
    int64 nTime = GetTimeMicros() - nStart;
    if (fBenchmark)
        printf("- Flush %i transactions: %.2fms (%.4fms/tx)\n", nModified, 0.001 * nTime, 0.001 * nTime / nModified);

    // Make sure it's successfully written to disk before changing memory structure
    bool fIsInitialDownload = IsInitialBlockDownload();
    if (!fIsInitialDownload || pcoinsTip->GetCacheSize() > nCoinCacheSize) {
        // Typical CCoins structures on disk are around 100 bytes in size.
        // Pushing a new one to the database can cause it to be written
        // twice (once in the log, and once in the tables). This is already
        // an overestimation, as most will delete an existing entry or
        // overwrite one. Still, use a conservative safety factor of 2.
        if (!CheckDiskSpace(100 * 2 * 2 * pcoinsTip->GetCacheSize()))
            return state.Error();
        FlushBlockFile();
        pblocktree->Sync();
        if (!pcoinsTip->Flush())
            return state.Abort(_("Failed to write to coin database"));
    }

    // At this point, all changes have been done to the database.
    // Proceed by updating the memory structures.

    // Disconnect shorter branch
    BOOST_FOREACH(CBlockIndex* pindex, vDisconnect)
        if (pindex->pprev)
            pindex->pprev->pnext = NULL;

    // Connect longer branch
    BOOST_FOREACH(CBlockIndex* pindex, vConnect)
        if (pindex->pprev)
            pindex->pprev->pnext = pindex;

    // Resurrect memory transactions that were in the disconnected branch
    BOOST_FOREACH(CTransaction& tx, vResurrect) {
        // ignore validation errors in resurrected transactions
        CValidationState stateDummy;
        if (!tx.AcceptToMemoryPool(stateDummy, true, false))
            mempool.remove(tx, true);
    }

    // Delete redundant memory transactions that are in the connected branch
    BOOST_FOREACH(CTransaction& tx, vDelete) {
        mempool.remove(tx);
        mempool.removeConflicts(tx);
    }

    // Update best block in wallet (so we can detect restored wallets)
    if ((pindexNew->nHeight % 20160) == 0 || (!fIsInitialDownload && (pindexNew->nHeight % 144) == 0))
    {
        const CBlockLocator locator(pindexNew);
        ::SetBestChain(locator);
    }

    // New best block
    hashBestChain = pindexNew->GetBlockHash();
    pindexBest = pindexNew;
    pblockindexFBBHLast = NULL;
    nBestHeight = pindexBest->nHeight;
    nBestChainWork = pindexNew->nChainWork;
    nTimeBestReceived = GetTime();
    nTransactionsUpdated++;
    printf("SetBestChain: new best=%s  height=%d  log2_work=%.8g  tx=%lu  date=%s progress=%f\n",
      hashBestChain.ToString().c_str(), nBestHeight, log(nBestChainWork.getdouble())/log(2.0), (unsigned long)pindexNew->nChainTx,
      DateTimeStrFormat("%Y-%m-%d %H:%M:%S", pindexBest->GetBlockTime()).c_str(),
      Checkpoints::GuessVerificationProgress(pindexBest));

    // Check the version of the last 100 blocks to see if we need to upgrade:
    if (!fIsInitialDownload)
    {
        int nUpgraded = 0;
        const CBlockIndex* pindex = pindexBest;
        for (int i = 0; i < 100 && pindex != NULL; i++)
        {
            if (pindex->nVersion > CBlock::CURRENT_VERSION)
                ++nUpgraded;
            pindex = pindex->pprev;
        }
        if (nUpgraded > 0)
            printf("SetBestChain: %d of last 100 blocks above version %d\n", nUpgraded, CBlock::CURRENT_VERSION);
        if (nUpgraded > 100/2)
            // strMiscWarning is read by GetWarnings(), called by Qt and the JSON-RPC code to warn the user:
            strMiscWarning = _("Warning: This version is obsolete, upgrade required!");
    }

    std::string strCmd = GetArg("-blocknotify", "");

    if (!fIsInitialDownload && !strCmd.empty())
    {
        boost::replace_all(strCmd, "%s", hashBestChain.GetHex());
        boost::thread t(runCommand, strCmd); // thread runs free
    }

    return true;
}


bool CBlock::AddToBlockIndex(CValidationState &state, const CDiskBlockPos &pos)
{
    // Check for duplicate
    uint256 hash = GetHash();
    if (mapBlockIndex.count(hash))
        return state.Invalid(error("AddToBlockIndex() : %s already exists", hash.ToString().c_str()));

    // Construct new block index object
    CBlockIndex* pindexNew = new CBlockIndex(*this);
    assert(pindexNew);
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.insert(make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);
    map<uint256, CBlockIndex*>::iterator miPrev = mapBlockIndex.find(hashPrevBlock);
    if (miPrev != mapBlockIndex.end())
    {
        pindexNew->pprev = (*miPrev).second;
        pindexNew->nHeight = pindexNew->pprev->nHeight + 1;
    }
    pindexNew->nTx = vtx.size();
    pindexNew->nChainWork = (pindexNew->pprev ? pindexNew->pprev->nChainWork : 0) + pindexNew->GetBlockWork().getuint256();
    pindexNew->nChainTx = (pindexNew->pprev ? pindexNew->pprev->nChainTx : 0) + pindexNew->nTx;
    pindexNew->nFile = pos.nFile;
    pindexNew->nDataPos = pos.nPos;
    pindexNew->nUndoPos = 0;
    pindexNew->nStatus = BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA;
    setBlockIndexValid.insert(pindexNew);

    if (!pblocktree->WriteBlockIndex(CDiskBlockIndex(pindexNew)))
        return state.Abort(_("Failed to write block index"));

    // New best?
    if (!ConnectBestBlock(state))
        return false;

    if (pindexNew == pindexBest)
    {
        // Notify UI to display prev block's coinbase if it was ours
        static uint256 hashPrevBestCoinBase;
        UpdatedTransaction(hashPrevBestCoinBase);
        hashPrevBestCoinBase = GetTxHash(0);
    }

    if (!pblocktree->Flush())
        return state.Abort(_("Failed to sync block index"));

    uiInterface.NotifyBlocksChanged();
    return true;
}


bool FindBlockPos(CValidationState &state, CDiskBlockPos &pos, unsigned int nAddSize, unsigned int nHeight, uint64 nTime, bool fKnown = false)
{
    bool fUpdatedLast = false;

    LOCK(cs_LastBlockFile);

    if (fKnown) {
        if (nLastBlockFile != pos.nFile) {
            nLastBlockFile = pos.nFile;
            infoLastBlockFile.SetNull();
            pblocktree->ReadBlockFileInfo(nLastBlockFile, infoLastBlockFile);
            fUpdatedLast = true;
        }
    } else {
        while (infoLastBlockFile.nSize + nAddSize >= MAX_BLOCKFILE_SIZE) {
            printf("Leaving block file %i: %s\n", nLastBlockFile, infoLastBlockFile.ToString().c_str());
            FlushBlockFile(true);
            nLastBlockFile++;
            infoLastBlockFile.SetNull();
            pblocktree->ReadBlockFileInfo(nLastBlockFile, infoLastBlockFile); // check whether data for the new file somehow already exist; can fail just fine
            fUpdatedLast = true;
        }
        pos.nFile = nLastBlockFile;
        pos.nPos = infoLastBlockFile.nSize;
    }

    infoLastBlockFile.nSize += nAddSize;
    infoLastBlockFile.AddBlock(nHeight, nTime);

    if (!fKnown) {
        unsigned int nOldChunks = (pos.nPos + BLOCKFILE_CHUNK_SIZE - 1) / BLOCKFILE_CHUNK_SIZE;
        unsigned int nNewChunks = (infoLastBlockFile.nSize + BLOCKFILE_CHUNK_SIZE - 1) / BLOCKFILE_CHUNK_SIZE;
        if (nNewChunks > nOldChunks) {
            if (CheckDiskSpace(nNewChunks * BLOCKFILE_CHUNK_SIZE - pos.nPos)) {
                FILE *file = OpenBlockFile(pos);
                if (file) {
                    printf("Pre-allocating up to position 0x%x in blk%05u.dat\n", nNewChunks * BLOCKFILE_CHUNK_SIZE, pos.nFile);
                    AllocateFileRange(file, pos.nPos, nNewChunks * BLOCKFILE_CHUNK_SIZE - pos.nPos);
                    fclose(file);
                }
            }
            else
                return state.Error();
        }
    }

    if (!pblocktree->WriteBlockFileInfo(nLastBlockFile, infoLastBlockFile))
        return state.Abort(_("Failed to write file info"));
    if (fUpdatedLast)
        pblocktree->WriteLastBlockFile(nLastBlockFile);

    return true;
}

bool FindUndoPos(CValidationState &state, int nFile, CDiskBlockPos &pos, unsigned int nAddSize)
{
    pos.nFile = nFile;

    LOCK(cs_LastBlockFile);

    unsigned int nNewSize;
    if (nFile == nLastBlockFile) {
        pos.nPos = infoLastBlockFile.nUndoSize;
        nNewSize = (infoLastBlockFile.nUndoSize += nAddSize);
        if (!pblocktree->WriteBlockFileInfo(nLastBlockFile, infoLastBlockFile))
            return state.Abort(_("Failed to write block info"));
    } else {
        CBlockFileInfo info;
        if (!pblocktree->ReadBlockFileInfo(nFile, info))
            return state.Abort(_("Failed to read block info"));
        pos.nPos = info.nUndoSize;
        nNewSize = (info.nUndoSize += nAddSize);
        if (!pblocktree->WriteBlockFileInfo(nFile, info))
            return state.Abort(_("Failed to write block info"));
    }

    unsigned int nOldChunks = (pos.nPos + UNDOFILE_CHUNK_SIZE - 1) / UNDOFILE_CHUNK_SIZE;
    unsigned int nNewChunks = (nNewSize + UNDOFILE_CHUNK_SIZE - 1) / UNDOFILE_CHUNK_SIZE;
    if (nNewChunks > nOldChunks) {
        if (CheckDiskSpace(nNewChunks * UNDOFILE_CHUNK_SIZE - pos.nPos)) {
            FILE *file = OpenUndoFile(pos);
            if (file) {
                printf("Pre-allocating up to position 0x%x in rev%05u.dat\n", nNewChunks * UNDOFILE_CHUNK_SIZE, pos.nFile);
                AllocateFileRange(file, pos.nPos, nNewChunks * UNDOFILE_CHUNK_SIZE - pos.nPos);
                fclose(file);
            }
        }
        else
            return state.Error();
    }

    return true;
}


bool CBlock::CheckBlock(CValidationState &state, bool fCheckPOW, bool fCheckMerkleRoot) const
{
    // These are checks that are independent of context
    // that can be verified before saving an orphan block.

    // Size limits
    if (vtx.empty() || vtx.size() > MAX_BLOCK_SIZE || ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION) > MAX_BLOCK_SIZE)
        return state.DoS(100, error("CheckBlock() : size limits failed"));

    // Crypto: Special short-term limits to avoid 10,000 BDB lock limit:
    if (GetBlockTime() < 1376568000)  // stop enforcing 15 August 2013 00:00:00
    {
        // Rule is: #unique txids referenced <= 4,500
        // ... to prevent 10,000 BDB lock exhaustion on old clients
        set<uint256> setTxIn;
        for (size_t i = 0; i < vtx.size(); i++)
        {
            setTxIn.insert(vtx[i].GetHash());
            if (i == 0) continue; // skip coinbase txin
            BOOST_FOREACH(const CTxIn& txin, vtx[i].vin)
                setTxIn.insert(txin.prevout.hash);
        }
        size_t nTxids = setTxIn.size();
        if (nTxids > 4500)
            return error("CheckBlock() : 15 August maxlocks violation");
    }
	
	CBlockIndex* pindexPrev = NULL;
    int nHeight = 0;
    if (GetHash() != hashGenesisBlock)
    {
        map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashPrevBlock);
        pindexPrev = (*mi).second;
		if (!(pindexPrev == NULL))
		{
			nHeight = pindexPrev->nHeight+1;
            // Check proof of work matches claimed amount
            if (fCheckPOW && !CheckProofOfWork(GetPoWHash(nHeight), nBits))
                return state.DoS(50, error("CheckBlock() : proof of work failed"));
		}
    }

    // Check timestamp
    if (GetBlockTime() > GetAdjustedTime() + 2 * 60 * 60)
        return state.Invalid(error("CheckBlock() : block timestamp too far in the future"));

    // First transaction must be coinbase, the rest must not be
    if (vtx.empty() || !vtx[0].IsCoinBase())
        return state.DoS(100, error("CheckBlock() : first tx is not coinbase"));
    for (unsigned int i = 1; i < vtx.size(); i++)
        if (vtx[i].IsCoinBase())
            return state.DoS(100, error("CheckBlock() : more than one coinbase"));

    // Check transactions
    BOOST_FOREACH(const CTransaction& tx, vtx)
        if (!tx.CheckTransaction(state))
            return error("CheckBlock() : CheckTransaction failed");

    // Build the merkle tree already. We need it anyway later, and it makes the
    // block cache the transaction hashes, which means they don't need to be
    // recalculated many times during this block's validation.
    BuildMerkleTree();

    // Check for duplicate txids. This is caught by ConnectInputs(),
    // but catching it earlier avoids a potential DoS attack:
    set<uint256> uniqueTx;
    for (unsigned int i=0; i<vtx.size(); i++) {
        uniqueTx.insert(GetTxHash(i));
    }
    if (uniqueTx.size() != vtx.size())
        return state.DoS(100, error("CheckBlock() : duplicate transaction"), true);

    unsigned int nSigOps = 0;
    BOOST_FOREACH(const CTransaction& tx, vtx)
    {
        nSigOps += tx.GetLegacySigOpCount();
    }
    if (nSigOps > MAX_BLOCK_SIGOPS)
        return state.DoS(100, error("CheckBlock() : out-of-bounds SigOpCount"));

    // Check merkle root
    if (fCheckMerkleRoot && hashMerkleRoot != BuildMerkleTree())
        return state.DoS(100, error("CheckBlock() : hashMerkleRoot mismatch"));

    return true;
}

bool CBlock::AcceptBlock(CValidationState &state, CDiskBlockPos *dbp)
{
    // Check for duplicate
    uint256 hash = GetHash();
    if (mapBlockIndex.count(hash))
        return state.Invalid(error("AcceptBlock() : block already in mapBlockIndex"));

    // Get prev block index
    CBlockIndex* pindexPrev = NULL;
    int nHeight = 0;
    if (hash != hashGenesisBlock) {
        map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashPrevBlock);
        if (mi == mapBlockIndex.end())
            return state.DoS(10, error("AcceptBlock() : prev block not found"));
        pindexPrev = (*mi).second;
        nHeight = pindexPrev->nHeight+1;
        LastHeight = pindexPrev->nHeight;

        // Check proof of work
       if (nBits != GetNextWorkRequired(pindexPrev, this))
            return state.DoS(100, error("AcceptBlock() : incorrect proof of work"));

        // Check timestamp against prev
        if (GetBlockTime() <= pindexPrev->GetMedianTimePast())
            return state.Invalid(error("AcceptBlock() : block's timestamp is too early"));

        // Check that all transactions are finalized
        BOOST_FOREACH(const CTransaction& tx, vtx)
            if (!tx.IsFinal(nHeight, GetBlockTime()))
                return state.DoS(10, error("AcceptBlock() : contains a non-final transaction"));

        // Check that the block chain matches the known block chain up to a checkpoint
        if (!Checkpoints::CheckBlock(nHeight, hash))
            return state.DoS(100, error("AcceptBlock() : rejected by checkpoint lock-in at %d", nHeight));

        // Don't accept any forks from the main chain prior to last checkpoint
        CBlockIndex* pcheckpoint = Checkpoints::GetLastCheckpoint(mapBlockIndex);
        if (pcheckpoint && nHeight < pcheckpoint->nHeight)
            return state.DoS(100, error("AcceptBlock() : forked chain older than last checkpoint (height %d)", nHeight));

        // Reject block.nVersion=1 or =2 blocks when 95% (75% on testnet) of the network has upgraded:
        if (nVersion < 3)
        {
            if ((!fTestNet && CBlockIndex::IsSuperMajority(3, pindexPrev, 950, 1000)) ||
                (fTestNet && CBlockIndex::IsSuperMajority(3, pindexPrev, 75, 100)))
            {
                return state.Invalid(error("AcceptBlock() : rejected old nVersion block"));
            }
        }
        // Enforce block.nVersion=2 rule that the coinbase starts with serialized block height
        if (nVersion >= 2)
        {
            // if 750 of the last 1,000 blocks are version 2 or greater (51/100 if testnet):
            if ((!fTestNet && CBlockIndex::IsSuperMajority(2, pindexPrev, 750, 1000)) ||
                (fTestNet && CBlockIndex::IsSuperMajority(2, pindexPrev, 51, 100)))
            {
                CScript expect = CScript() << nHeight;
                if (vtx[0].vin[0].scriptSig.size() < expect.size() ||
                    !std::equal(expect.begin(), expect.end(), vtx[0].vin[0].scriptSig.begin()))
                    return state.DoS(100, error("AcceptBlock() : block height mismatch in coinbase"));
            }
        }
    }

    // Write block to history file
    try {
        unsigned int nBlockSize = ::GetSerializeSize(*this, SER_DISK, CLIENT_VERSION);
        CDiskBlockPos blockPos;
        if (dbp != NULL)
            blockPos = *dbp;
        if (!FindBlockPos(state, blockPos, nBlockSize+8, nHeight, nTime, dbp != NULL))
            return error("AcceptBlock() : FindBlockPos failed");
        if (dbp == NULL)
            if (!WriteToDisk(blockPos))
                return state.Abort(_("Failed to write block"));
        if (!AddToBlockIndex(state, blockPos))
            return error("AcceptBlock() : AddToBlockIndex failed");
    } catch(std::runtime_error &e) {
        return state.Abort(_("System error: ") + e.what());
    }

    // Relay inventory, but don't relay old inventory during initial block download
    int nBlockEstimate = Checkpoints::GetTotalBlocksEstimate();
    if (hashBestChain == hash)
    {
        LOCK(cs_vNodes);
        BOOST_FOREACH(CNode* pnode, vNodes)
            if (nBestHeight > (pnode->nStartingHeight != -1 ? pnode->nStartingHeight - 2000 : nBlockEstimate))
                pnode->PushInventory(CInv(MSG_BLOCK, hash));
    }

    return true;
}

bool CBlockIndex::IsSuperMajority(int minVersion, const CBlockIndex* pstart, unsigned int nRequired, unsigned int nToCheck)
{
    // Crypto: temporarily disable v2 block lockin until we are ready for v2 transition
    return false;
    unsigned int nFound = 0;
    for (unsigned int i = 0; i < nToCheck && nFound < nRequired && pstart != NULL; i++)
    {
        if (pstart->nVersion >= minVersion)
            ++nFound;
        pstart = pstart->pprev;
    }
    return (nFound >= nRequired);
}

bool ProcessBlock(CValidationState &state, CNode* pfrom, CBlock* pblock, CDiskBlockPos *dbp)
{
    // Check for duplicate
    uint256 hash = pblock->GetHash();
    if (mapBlockIndex.count(hash))
        return state.Invalid(error("ProcessBlock() : already have block %d %s", mapBlockIndex[hash]->nHeight, hash.ToString().c_str()));
    if (mapOrphanBlocks.count(hash))
        return state.Invalid(error("ProcessBlock() : already have block (orphan) %s", hash.ToString().c_str()));

    // Preliminary checks
    if (!pblock->CheckBlock(state))
        return error("ProcessBlock() : CheckBlock FAILED");

    CBlockIndex* pcheckpoint = Checkpoints::GetLastCheckpoint(mapBlockIndex);
    if (pcheckpoint && pblock->hashPrevBlock != hashBestChain)
    {
        // Extra checks to prevent "fill up memory by spamming with bogus blocks"
        int64 deltaTime = pblock->GetBlockTime() - pcheckpoint->nTime;
        if (deltaTime < 0)
        {
            return state.DoS(100, error("ProcessBlock() : block with timestamp before last checkpoint"));
        }
        CBigNum bnNewBlock;
        bnNewBlock.SetCompact(pblock->nBits);
        CBigNum bnRequired;
        bnRequired.SetCompact(ComputeMinWork(pcheckpoint->nBits, deltaTime));
        if (bnNewBlock > bnRequired)
        {
            return state.DoS(100, error("ProcessBlock() : block with too little proof-of-work"));
        }
    }


    // If we don't already have its previous block, shunt it off to holding area until we get it
    if (pblock->hashPrevBlock != 0 && !mapBlockIndex.count(pblock->hashPrevBlock))
    {
        printf("ProcessBlock: ORPHAN BLOCK, prev=%s\n", pblock->hashPrevBlock.ToString().c_str());

        // Accept orphans as long as there is a node to request its parents from
        if (pfrom) {
            CBlock* pblock2 = new CBlock(*pblock);
            mapOrphanBlocks.insert(make_pair(hash, pblock2));
            mapOrphanBlocksByPrev.insert(make_pair(pblock2->hashPrevBlock, pblock2));

            // Ask this guy to fill in what we're missing
            pfrom->PushGetBlocks(pindexBest, GetOrphanRoot(pblock2));
        }
        return true;
    }

    // Store to disk
    if (!pblock->AcceptBlock(state, dbp))
        return error("ProcessBlock() : AcceptBlock FAILED");

    // Recursively process any orphan blocks that depended on this one
    vector<uint256> vWorkQueue;
    vWorkQueue.push_back(hash);
    for (unsigned int i = 0; i < vWorkQueue.size(); i++)
    {
        uint256 hashPrev = vWorkQueue[i];
        for (multimap<uint256, CBlock*>::iterator mi = mapOrphanBlocksByPrev.lower_bound(hashPrev);
             mi != mapOrphanBlocksByPrev.upper_bound(hashPrev);
             ++mi)
        {
            CBlock* pblockOrphan = (*mi).second;
            // Use a dummy CValidationState so someone can't setup nodes to counter-DoS based on orphan resolution (that is, feeding people an invalid block based on LegitBlockX in order to get anyone relaying LegitBlockX banned)
            CValidationState stateDummy;
            if (pblockOrphan->AcceptBlock(stateDummy))
                vWorkQueue.push_back(pblockOrphan->GetHash());
            mapOrphanBlocks.erase(pblockOrphan->GetHash());
            delete pblockOrphan;
        }
        mapOrphanBlocksByPrev.erase(hashPrev);
    }
	
	if(!fReindex)
	{
		// Check that all transactions are have OP_RETURN
		list<CStealthAddressEntry> listStealthAddress;
		CWalletDB(pwalletMain->strWalletFile).ListStealthAddress("*", listStealthAddress);

		BOOST_FOREACH(const CTransaction& tx, pblock->vtx){
			vector<CTxOut> vtxOut;
			vtxOut = tx.vout;
			bool IsStealthTx = false;

			vector<boost::tuple<string, ec_secret, ec_secret, ec_point, string> > vRecvAddress;
			ec_secret scan_secret;
			ec_secret spend_secret;
			ec_point spend_pubkey;
			ec_point ephem_pubkey;
			   
			   
			// check sx transaction
			for(unsigned int i = 0; i < vtxOut.size(); i++){
				CTxOut txOut;
				txOut = vtxOut[i];
					
				if(txOut.scriptPubKey[0] == OP_RETURN && txOut.scriptPubKey[1] == 0x21){

					// set flag
					IsStealthTx = true;

					// clear old ephem_pubkey
					ephem_pubkey.clear();

					// extract ephem_pubkey
					ephem_pubkey.insert(ephem_pubkey.end(), txOut.scriptPubKey.begin() + 2, txOut.scriptPubKey.begin() + 35);

					// generate Crypto address from ephem_pubkey, scan_secret and spend_secret
					BOOST_FOREACH(const CStealthAddressEntry& stealthAddress, listStealthAddress)
					{
						for(unsigned int i = 0; i < 32; i++)
						{
							scan_secret[i] = stealthAddress.scanSecret[i];
							spend_secret[i] = stealthAddress.spendSecret[i];
						}

						spend_pubkey = secret_to_public_key(spend_secret, true);
						ec_point uncover_pubkey = uncover_stealth(ephem_pubkey, scan_secret, spend_pubkey);
						payment_address return_addr;
						set_public_key(return_addr, uncover_pubkey);
						string strRevcAddress = return_addr.encoded();
						vRecvAddress.push_back(boost::make_tuple(strRevcAddress, scan_secret, spend_secret, ephem_pubkey, stealthAddress.stealthAddress));
					}
				}
			}



			if(IsStealthTx){
			   // check match address
				for(unsigned int i = 0; i < vtxOut.size(); i++){
					CTxOut txOut;
					txOut = vtxOut[i];
					CTxDestination txoutAddr;
					if(ExtractDestination(txOut.scriptPubKey, txoutAddr))
					{
						CBitcoinAddress bitAddr;
						bitAddr.Set(txoutAddr);

						BOOST_FOREACH(const TUPLETYPE(string, ec_secret, ec_secret, ec_point, string)& item, vRecvAddress)
						{
							if(boost::get<0>(item).compare(bitAddr.ToString()) == 0){
								ec_secret secret = uncover_stealth_secret(boost::get<3>(item), boost::get<1>(item), boost::get<2>(item));

								string wif_result = secret_to_wif(secret, true);

								// store wif
								CWalletDB walletdb(pwalletMain->strWalletFile);
								CStealthAddressWifEntry itemImportWif;
								itemImportWif.stealthAddress = boost::get<4>(item);
								itemImportWif.wif = wif_result;
								walletdb.WriteImportedSxWifEntry(itemImportWif, false);
								printf("\n write wif content to wallet\n");
							}
						}
					}
				}
			}

		}
	}

    printf("ProcessBlock: ACCEPTED\n");

	return true;
}







CMerkleBlock::CMerkleBlock(const CBlock& block, CBloomFilter& filter)
{
    header = block.GetBlockHeader();

    vector<bool> vMatch;
    vector<uint256> vHashes;

    vMatch.reserve(block.vtx.size());
    vHashes.reserve(block.vtx.size());

    for (unsigned int i = 0; i < block.vtx.size(); i++)
    {
        uint256 hash = block.vtx[i].GetHash();
        if (filter.IsRelevantAndUpdate(block.vtx[i], hash))
        {
            vMatch.push_back(true);
            vMatchedTxn.push_back(make_pair(i, hash));
        }
        else
            vMatch.push_back(false);
        vHashes.push_back(hash);
    }

    txn = CPartialMerkleTree(vHashes, vMatch);
}








uint256 CPartialMerkleTree::CalcHash(int height, unsigned int pos, const std::vector<uint256> &vTxid) {
    if (height == 0) {
        // hash at height 0 is the txids themself
        return vTxid[pos];
    } else {
        // calculate left hash
        uint256 left = CalcHash(height-1, pos*2, vTxid), right;
        // calculate right hash if not beyong the end of the array - copy left hash otherwise1
        if (pos*2+1 < CalcTreeWidth(height-1))
            right = CalcHash(height-1, pos*2+1, vTxid);
        else
            right = left;
        // combine subhashes
        return Hash(BEGIN(left), END(left), BEGIN(right), END(right));
    }
}

void CPartialMerkleTree::TraverseAndBuild(int height, unsigned int pos, const std::vector<uint256> &vTxid, const std::vector<bool> &vMatch) {
    // determine whether this node is the parent of at least one matched txid
    bool fParentOfMatch = false;
    for (unsigned int p = pos << height; p < (pos+1) << height && p < nTransactions; p++)
        fParentOfMatch |= vMatch[p];
    // store as flag bit
    vBits.push_back(fParentOfMatch);
    if (height==0 || !fParentOfMatch) {
        // if at height 0, or nothing interesting below, store hash and stop
        vHash.push_back(CalcHash(height, pos, vTxid));
    } else {
        // otherwise, don't store any hash, but descend into the subtrees
        TraverseAndBuild(height-1, pos*2, vTxid, vMatch);
        if (pos*2+1 < CalcTreeWidth(height-1))
            TraverseAndBuild(height-1, pos*2+1, vTxid, vMatch);
    }
}

uint256 CPartialMerkleTree::TraverseAndExtract(int height, unsigned int pos, unsigned int &nBitsUsed, unsigned int &nHashUsed, std::vector<uint256> &vMatch) {
    if (nBitsUsed >= vBits.size()) {
        // overflowed the bits array - failure
        fBad = true;
        return 0;
    }
    bool fParentOfMatch = vBits[nBitsUsed++];
    if (height==0 || !fParentOfMatch) {
        // if at height 0, or nothing interesting below, use stored hash and do not descend
        if (nHashUsed >= vHash.size()) {
            // overflowed the hash array - failure
            fBad = true;
            return 0;
        }
        const uint256 &hash = vHash[nHashUsed++];
        if (height==0 && fParentOfMatch) // in case of height 0, we have a matched txid
            vMatch.push_back(hash);
        return hash;
    } else {
        // otherwise, descend into the subtrees to extract matched txids and hashes
        uint256 left = TraverseAndExtract(height-1, pos*2, nBitsUsed, nHashUsed, vMatch), right;
        if (pos*2+1 < CalcTreeWidth(height-1))
            right = TraverseAndExtract(height-1, pos*2+1, nBitsUsed, nHashUsed, vMatch);
        else
            right = left;
        // and combine them before returning
        return Hash(BEGIN(left), END(left), BEGIN(right), END(right));
    }
}

CPartialMerkleTree::CPartialMerkleTree(const std::vector<uint256> &vTxid, const std::vector<bool> &vMatch) : nTransactions(vTxid.size()), fBad(false) {
    // reset state
    vBits.clear();
    vHash.clear();

    // calculate height of tree
    int nHeight = 0;
    while (CalcTreeWidth(nHeight) > 1)
        nHeight++;

    // traverse the partial tree
    TraverseAndBuild(nHeight, 0, vTxid, vMatch);
}

CPartialMerkleTree::CPartialMerkleTree() : nTransactions(0), fBad(true) {}

uint256 CPartialMerkleTree::ExtractMatches(std::vector<uint256> &vMatch) {
    vMatch.clear();
    // An empty set will not work
    if (nTransactions == 0)
        return 0;
    // check for excessively high numbers of transactions
    if (nTransactions > MAX_BLOCK_SIZE / 60) // 60 is the lower bound for the size of a serialized CTransaction
        return 0;
    // there can never be more hashes provided than one for every txid
    if (vHash.size() > nTransactions)
        return 0;
    // there must be at least one bit per node in the partial tree, and at least one node per hash
    if (vBits.size() < vHash.size())
        return 0;
    // calculate height of tree
    int nHeight = 0;
    while (CalcTreeWidth(nHeight) > 1)
        nHeight++;
    // traverse the partial tree
    unsigned int nBitsUsed = 0, nHashUsed = 0;
    uint256 hashMerkleRoot = TraverseAndExtract(nHeight, 0, nBitsUsed, nHashUsed, vMatch);
    // verify that no problems occured during the tree traversal
    if (fBad)
        return 0;
    // verify that all bits were consumed (except for the padding caused by serializing it as a byte sequence)
    if ((nBitsUsed+7)/8 != (vBits.size()+7)/8)
        return 0;
    // verify that all hashes were consumed
    if (nHashUsed != vHash.size())
        return 0;
    return hashMerkleRoot;
}







bool AbortNode(const std::string &strMessage) {
    strMiscWarning = strMessage;
    printf("*** %s\n", strMessage.c_str());
    uiInterface.ThreadSafeMessageBox(strMessage, "", CClientUIInterface::MSG_ERROR);
    StartShutdown();
    return false;
}

bool CheckDiskSpace(uint64 nAdditionalBytes)
{
    uint64 nFreeBytesAvailable = filesystem::space(GetDataDir()).available;

    // Check for nMinDiskSpace bytes (currently 50MB)
    if (nFreeBytesAvailable < nMinDiskSpace + nAdditionalBytes)
        return AbortNode(_("Error: Disk space is low!"));

    return true;
}

CCriticalSection cs_LastBlockFile;
CBlockFileInfo infoLastBlockFile;
int nLastBlockFile = 0;

FILE* OpenDiskFile(const CDiskBlockPos &pos, const char *prefix, bool fReadOnly)
{
    if (pos.IsNull())
        return NULL;
    boost::filesystem::path path = GetDataDir() / "blocks" / strprintf("%s%05u.dat", prefix, pos.nFile);
    boost::filesystem::create_directories(path.parent_path());
    FILE* file = fopen(path.string().c_str(), "rb+");
    if (!file && !fReadOnly)
        file = fopen(path.string().c_str(), "wb+");
    if (!file) {
        printf("Unable to open file %s\n", path.string().c_str());
        return NULL;
    }
    if (pos.nPos) {
        if (fseek(file, pos.nPos, SEEK_SET)) {
            printf("Unable to seek to position %u of %s\n", pos.nPos, path.string().c_str());
            fclose(file);
            return NULL;
        }
    }
    return file;
}

FILE* OpenBlockFile(const CDiskBlockPos &pos, bool fReadOnly) {
    return OpenDiskFile(pos, "blk", fReadOnly);
}

FILE* OpenUndoFile(const CDiskBlockPos &pos, bool fReadOnly) {
    return OpenDiskFile(pos, "rev", fReadOnly);
}

CBlockIndex * InsertBlockIndex(uint256 hash)
{
    if (hash == 0)
        return NULL;

    // Return existing
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
    if (mi != mapBlockIndex.end())
        return (*mi).second;

    // Create new
    CBlockIndex* pindexNew = new CBlockIndex();
    if (!pindexNew)
        throw runtime_error("LoadBlockIndex() : new CBlockIndex failed");
    mi = mapBlockIndex.insert(make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);

    return pindexNew;
}

bool static LoadBlockIndexDB()
{
    if (!pblocktree->LoadBlockIndexGuts())
        return false;

    boost::this_thread::interruption_point();

    // Calculate nChainWork
    vector<pair<int, CBlockIndex*> > vSortedByHeight;
    vSortedByHeight.reserve(mapBlockIndex.size());
    BOOST_FOREACH(const PAIRTYPE(uint256, CBlockIndex*)& item, mapBlockIndex)
    {
        CBlockIndex* pindex = item.second;
        vSortedByHeight.push_back(make_pair(pindex->nHeight, pindex));
    }
    sort(vSortedByHeight.begin(), vSortedByHeight.end());
    BOOST_FOREACH(const PAIRTYPE(int, CBlockIndex*)& item, vSortedByHeight)
    {
        CBlockIndex* pindex = item.second;
        pindex->nChainWork = (pindex->pprev ? pindex->pprev->nChainWork : 0) + pindex->GetBlockWork().getuint256();
        pindex->nChainTx = (pindex->pprev ? pindex->pprev->nChainTx : 0) + pindex->nTx;
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_TRANSACTIONS && !(pindex->nStatus & BLOCK_FAILED_MASK))
            setBlockIndexValid.insert(pindex);
    }

    // Load block file info
    pblocktree->ReadLastBlockFile(nLastBlockFile);
    printf("LoadBlockIndexDB(): last block file = %i\n", nLastBlockFile);
    if (pblocktree->ReadBlockFileInfo(nLastBlockFile, infoLastBlockFile))
        printf("LoadBlockIndexDB(): last block file info: %s\n", infoLastBlockFile.ToString().c_str());

    // Load nBestInvalidWork, OK if it doesn't exist
    CBigNum bnBestInvalidWork;
    pblocktree->ReadBestInvalidWork(bnBestInvalidWork);
    nBestInvalidWork = bnBestInvalidWork.getuint256();

    // Check whether we need to continue reindexing
    bool fReindexing = false;
    pblocktree->ReadReindexing(fReindexing);
    fReindex |= fReindexing;

    // Check whether we have a transaction index
    pblocktree->ReadFlag("txindex", fTxIndex);
    printf("LoadBlockIndexDB(): transaction index %s\n", fTxIndex ? "enabled" : "disabled");

    // Load hashBestChain pointer to end of best chain
    pindexBest = pcoinsTip->GetBestBlock();
    if (pindexBest == NULL)
        return true;
    hashBestChain = pindexBest->GetBlockHash();
    nBestHeight = pindexBest->nHeight;
    nBestChainWork = pindexBest->nChainWork;

    // set 'next' pointers in best chain
    CBlockIndex *pindex = pindexBest;
    while(pindex != NULL && pindex->pprev != NULL) {
         CBlockIndex *pindexPrev = pindex->pprev;
         pindexPrev->pnext = pindex;
         pindex = pindexPrev;
    }
    printf("LoadBlockIndexDB(): hashBestChain=%s  height=%d date=%s\n",
        hashBestChain.ToString().c_str(), nBestHeight,
        DateTimeStrFormat("%Y-%m-%d %H:%M:%S", pindexBest->GetBlockTime()).c_str());

    return true;
}

bool VerifyDB(int nCheckLevel, int nCheckDepth)
{
    if (pindexBest == NULL || pindexBest->pprev == NULL)
        return true;

    // Verify blocks in the best chain
    if (nCheckDepth <= 0)
        nCheckDepth = 1000000000; // suffices until the year 19000
    if (nCheckDepth > nBestHeight)
        nCheckDepth = nBestHeight;
    nCheckLevel = std::max(0, std::min(4, nCheckLevel));
    printf("Verifying last %i blocks at level %i\n", nCheckDepth, nCheckLevel);
    CCoinsViewCache coins(*pcoinsTip, true);
    CBlockIndex* pindexState = pindexBest;
    CBlockIndex* pindexFailure = NULL;
    int nGoodTransactions = 0;
    CValidationState state;
    for (CBlockIndex* pindex = pindexBest; pindex && pindex->pprev; pindex = pindex->pprev)
    {
        boost::this_thread::interruption_point();
        if (pindex->nHeight < nBestHeight-nCheckDepth)
            break;
        CBlock block;
        // check level 0: read from disk
        if (!block.ReadFromDisk(pindex))
            return error("VerifyDB() : *** block.ReadFromDisk failed at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString().c_str());
        // check level 1: verify block validity
        if (nCheckLevel >= 1 && !block.CheckBlock(state))
            return error("VerifyDB() : *** found bad block at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString().c_str());
        // check level 2: verify undo validity
        if (nCheckLevel >= 2 && pindex) {
            CBlockUndo undo;
            CDiskBlockPos pos = pindex->GetUndoPos();
            if (!pos.IsNull()) {
                if (!undo.ReadFromDisk(pos, pindex->pprev->GetBlockHash()))
                    return error("VerifyDB() : *** found bad undo data at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString().c_str());
            }
        }
        // check level 3: check for inconsistencies during memory-only disconnect of tip blocks
        if (nCheckLevel >= 3 && pindex == pindexState && (coins.GetCacheSize() + pcoinsTip->GetCacheSize()) <= 2*nCoinCacheSize + 32000) {
            bool fClean = true;
            if (!block.DisconnectBlock(state, pindex, coins, &fClean))
                return error("VerifyDB() : *** irrecoverable inconsistency in block data at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString().c_str());
            pindexState = pindex->pprev;
            if (!fClean) {
                nGoodTransactions = 0;
                pindexFailure = pindex;
            } else
                nGoodTransactions += block.vtx.size();
        }
    }
    if (pindexFailure)
        return error("VerifyDB() : *** coin database inconsistencies found (last %i blocks, %i good transactions before that)\n", pindexBest->nHeight - pindexFailure->nHeight + 1, nGoodTransactions);

    // check level 4: try reconnecting blocks
    if (nCheckLevel >= 4) {
        CBlockIndex *pindex = pindexState;
        while (pindex != pindexBest) {
            boost::this_thread::interruption_point();
            pindex = pindex->pnext;
            CBlock block;
            if (!block.ReadFromDisk(pindex))
                return error("VerifyDB() : *** block.ReadFromDisk failed at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString().c_str());
            if (!block.ConnectBlock(state, pindex, coins))
                return error("VerifyDB() : *** found unconnectable block at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString().c_str());
        }
    }

    printf("No coin database inconsistencies in last %i blocks (%i transactions)\n", pindexBest->nHeight - pindexState->nHeight, nGoodTransactions);

    return true;
}

void UnloadBlockIndex()
{
    mapBlockIndex.clear();
    setBlockIndexValid.clear();
    pindexGenesisBlock = NULL;
    nBestHeight = 0;
    nBestChainWork = 0;
    nBestInvalidWork = 0;
    hashBestChain = 0;
    pindexBest = NULL;
}

bool LoadBlockIndex()
{
    if (fTestNet)
    {
        pchMessageStart[0] = 0xf7;
        pchMessageStart[1] = 0xc1;
        pchMessageStart[2] = 0xd4;
        pchMessageStart[3] = 0xdc;
        hashGenesisBlock = uint256("0x1471f84b77a71ff798a39012823edd7d91b11ad7f2b90263a6bbbbe12c4d03fb");
    }

    //
    // Load block index from databases
    //
    if (!fReindex && !LoadBlockIndexDB())
        return false;

    return true;
}


bool InitBlockIndex() {
    // Check whether we're already initialized
    if (pindexGenesisBlock != NULL)
        return true;

    // Use the provided setting for -txindex in the new database
    fTxIndex = GetBoolArg("-txindex", false);
    pblocktree->WriteFlag("txindex", fTxIndex);
    printf("Initializing databases...\n");

    // Only add the genesis block if not reindexing (in which case we reuse the one already on disk)
    if (!fReindex) {

        // Genesis block
        const char* pszTimestamp = "The Metro 10/Feb/2015 A galaxy cluster captured by the Hubble telescope resembles a smiley face"; //Look, I am tired of all the sad news about terror and death, thus I chose this.
        CTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 0 << CBigNum(999) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 5 * COIN;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("041234710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9") << OP_CHECKSIG;;

        CBlock block;
        block.vtx.push_back(txNew);
        block.hashPrevBlock = 0;
        block.hashMerkleRoot = block.BuildMerkleTree();
        block.nVersion = 1;
        block.nBits    = 0x1e0ffff0;
        block.nNonce = 245191;
        block.nTime = 1423582740;

        if (fTestNet)
        {

            block.nNonce = 245191;
            block.nTime = 1423582740;
        }

        //// debug print
        uint256 hash = block.GetHash();
        printf("%s\n", hash.ToString().c_str());
        printf("%s\n", hashGenesisBlock.ToString().c_str());
        printf("%s\n", block.hashMerkleRoot.ToString().c_str());
        assert(block.hashMerkleRoot == uint256("0x6eedc084db1b0ac445de521816e455538cb813a6a468cd124b8c6708965047dd"));
            
        block.print();
        assert(hash == hashGenesisBlock);

        // Start new block file
        try {
            unsigned int nBlockSize = ::GetSerializeSize(block, SER_DISK, CLIENT_VERSION);
            CDiskBlockPos blockPos;
            CValidationState state;
            if (!FindBlockPos(state, blockPos, nBlockSize+8, 0, block.nTime))
                return error("LoadBlockIndex() : FindBlockPos failed");
            if (!block.WriteToDisk(blockPos))
                return error("LoadBlockIndex() : writing genesis block to disk failed");
            if (!block.AddToBlockIndex(state, blockPos))
                return error("LoadBlockIndex() : genesis block not accepted");
        } catch(std::runtime_error &e) {
            return error("LoadBlockIndex() : failed to initialize block database: %s", e.what());
        }
    }

    return true;
}



void PrintBlockTree()
{
    // pre-compute tree structure
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
        CBlock block;
        block.ReadFromDisk(pindex);
        printf("%d (blk%05u.dat:0x%x)  %s  tx %" PRIszu"",
            pindex->nHeight,
            pindex->GetBlockPos().nFile, pindex->GetBlockPos().nPos,
            DateTimeStrFormat("%Y-%m-%d %H:%M:%S", block.GetBlockTime()).c_str(),
            block.vtx.size());

        PrintWallets(block);

        // put the main time-chain first
        vector<CBlockIndex*>& vNext = mapNext[pindex];
        for (unsigned int i = 0; i < vNext.size(); i++)
        {
            if (vNext[i]->pnext)
            {
                swap(vNext[0], vNext[i]);
                break;
            }
        }

        // iterate children
        for (unsigned int i = 0; i < vNext.size(); i++)
            vStack.push_back(make_pair(nCol+i, vNext[i]));
    }
}

bool LoadExternalBlockFile(FILE* fileIn, CDiskBlockPos *dbp)
{
    int64 nStart = GetTimeMillis();

    int nLoaded = 0;
    try {
        CBufferedFile blkdat(fileIn, 2*MAX_BLOCK_SIZE, MAX_BLOCK_SIZE+8, SER_DISK, CLIENT_VERSION);
        uint64 nStartByte = 0;
        if (dbp) {
            // (try to) skip already indexed part
            CBlockFileInfo info;
            if (pblocktree->ReadBlockFileInfo(dbp->nFile, info)) {
                nStartByte = info.nSize;
                blkdat.Seek(info.nSize);
            }
        }
        uint64 nRewind = blkdat.GetPos();
        while (blkdat.good() && !blkdat.eof()) {
            boost::this_thread::interruption_point();

            blkdat.SetPos(nRewind);
            nRewind++; // start one byte further next time, in case of failure
            blkdat.SetLimit(); // remove former limit
            unsigned int nSize = 0;
            try {
                // locate a header
                unsigned char buf[4];
                blkdat.FindByte(pchMessageStart[0]);
                nRewind = blkdat.GetPos()+1;
                blkdat >> FLATDATA(buf);
                if (memcmp(buf, pchMessageStart, 4))
                    continue;
                // read size
                blkdat >> nSize;
                if (nSize < 80 || nSize > MAX_BLOCK_SIZE)
                    continue;
            } catch (std::exception &e) {
                // no valid block header found; don't complain
                break;
            }
            try {
                // read block
                uint64 nBlockPos = blkdat.GetPos();
                blkdat.SetLimit(nBlockPos + nSize);
                CBlock block;
                blkdat >> block;
                nRewind = blkdat.GetPos();

                // process block
                if (nBlockPos >= nStartByte) {
                    LOCK(cs_main);
                    if (dbp)
                        dbp->nPos = nBlockPos;
                    CValidationState state;
                    if (ProcessBlock(state, NULL, &block, dbp))
                        nLoaded++;
                    if (state.IsError())
                        break;
                }
            } catch (std::exception &e) {
                printf("%s() : Deserialize or I/O error caught during load\n", __PRETTY_FUNCTION__);
            }
        }
        fclose(fileIn);
    } catch(std::runtime_error &e) {
        AbortNode(_("Error: system error: ") + e.what());
    }
    if (nLoaded > 0)
        printf("Loaded %i blocks from external file in %" PRI64d"ms\n", nLoaded, GetTimeMillis() - nStart);
    return nLoaded > 0;
}










//////////////////////////////////////////////////////////////////////////////
//
// CAlert
//

extern map<uint256, CAlert> mapAlerts;
extern CCriticalSection cs_mapAlerts;

string GetWarnings(string strFor)
{
    int nPriority = 0;
    string strStatusBar;
    string strRPC;

    if (GetBoolArg("-testsafemode"))
        strRPC = "test";

    if (!CLIENT_VERSION_IS_RELEASE)
        strStatusBar = _("This is a pre-release test build - use at your own risk - do not use for mining or merchant applications");

    // Misc warnings like out of disk space and clock is wrong
    if (strMiscWarning != "")
    {
        nPriority = 1000;
        strStatusBar = strMiscWarning;
    }

    // Longer invalid proof-of-work chain
    if (pindexBest && nBestInvalidWork > nBestChainWork + (pindexBest->GetBlockWork() * 6).getuint256())
    {
        nPriority = 2000;
        strStatusBar = strRPC = _("Warning: Displayed transactions may not be correct! You may need to upgrade, or other nodes may need to upgrade.");
    }

    // Alerts
    {
        LOCK(cs_mapAlerts);
        BOOST_FOREACH(PAIRTYPE(const uint256, CAlert)& item, mapAlerts)
        {
            const CAlert& alert = item.second;
            if (alert.AppliesToMe() && alert.nPriority > nPriority)
            {
                nPriority = alert.nPriority;
                strStatusBar = alert.strStatusBar;
            }
        }
    }

    if (strFor == "statusbar")
        return strStatusBar;
    else if (strFor == "rpc")
        return strRPC;
    assert(!"GetWarnings() : invalid parameter");
    return "error";
}








//////////////////////////////////////////////////////////////////////////////
//
// Messages
//


bool static AlreadyHave(const CInv& inv)
{
    switch (inv.type)
    {
    case MSG_TX:
        {
            bool txInMap = false;
            {
                LOCK(mempool.cs);
                txInMap = mempool.exists(inv.hash);
            }
            return txInMap || mapOrphanTransactions.count(inv.hash) ||
                pcoinsTip->HaveCoins(inv.hash);
        }
    case MSG_BLOCK:
        return mapBlockIndex.count(inv.hash) ||
               mapOrphanBlocks.count(inv.hash);
    }
    // Don't know what it is, just say we already got one
    return true;
}




// The message start string is designed to be unlikely to occur in normal data.
// The characters are rarely used upper ASCII, not valid as UTF-8, and produce
// a large 4-byte int at any alignment.
unsigned char pchMessageStart[4] = { 0xa2, 0xc4, 0xb4, 0xda }; // Crypto: increase each by adding 1 to bitcoin's value.


void static ProcessGetData(CNode* pfrom)
{
    std::deque<CInv>::iterator it = pfrom->vRecvGetData.begin();

    vector<CInv> vNotFound;

    while (it != pfrom->vRecvGetData.end()) {
        // Don't bother if send buffer is too full to respond anyway
        if (pfrom->nSendSize >= SendBufferSize())
            break;

        // Don't waste work on slow peers until they catch up on the blocks we
        // give them. 80 bytes is just the size of a block header - obviously
        // the minimum we might return.
        if (pfrom->nBlocksRequested * 80 > pfrom->nSendBytes)
            break;

        const CInv &inv = *it;
        {
            boost::this_thread::interruption_point();
            it++;

            if (inv.type == MSG_BLOCK || inv.type == MSG_FILTERED_BLOCK)
            {
                bool send = true;
                map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(inv.hash);
                pfrom->nBlocksRequested++;
                if (mi != mapBlockIndex.end())
                {
                    // If the requested block is at a height below our last
                    // checkpoint, only serve it if it's in the checkpointed chain
                    int nHeight = ((*mi).second)->nHeight;
                    CBlockIndex* pcheckpoint = Checkpoints::GetLastCheckpoint(mapBlockIndex);
                    if (pcheckpoint && nHeight < pcheckpoint->nHeight) {
                       if (!((*mi).second)->IsInMainChain())
                       {
                         printf("ProcessGetData(): ignoring request for old block that isn't in the main chain\n");
                         send = false;
                       }
                    }
                } else {
                    send = false;
                }
                if (send)
                {
                    // Send block from disk
                    CBlock block;
                    block.ReadFromDisk((*mi).second);
                    if (inv.type == MSG_BLOCK)
                        pfrom->PushMessage("block", block);
                    else // MSG_FILTERED_BLOCK)
                    {
                        LOCK(pfrom->cs_filter);
                        if (pfrom->pfilter)
                        {
                            CMerkleBlock merkleBlock(block, *pfrom->pfilter);
                            pfrom->PushMessage("merkleblock", merkleBlock);
                            // CMerkleBlock just contains hashes, so also push any transactions in the block the client did not see
                            // This avoids hurting performance by pointlessly requiring a round-trip
                            // Note that there is currently no way for a node to request any single transactions we didnt send here -
                            // they must either disconnect and retry or request the full block.
                            // Thus, the protocol spec specified allows for us to provide duplicate txn here,
                            // however we MUST always provide at least what the remote peer needs
                            typedef std::pair<unsigned int, uint256> PairType;
                            BOOST_FOREACH(PairType& pair, merkleBlock.vMatchedTxn)
                                if (!pfrom->setInventoryKnown.count(CInv(MSG_TX, pair.second)))
                                    pfrom->PushMessage("tx", block.vtx[pair.first]);
                        }
                        // else
                            // no response
                    }

                    // Trigger them to send a getblocks request for the next batch of inventory
                    if (inv.hash == pfrom->hashContinue)
                    {
                        // Bypass PushInventory, this must send even if redundant,
                        // and we want it right after the last block so they don't
                        // wait for other stuff first.
                        vector<CInv> vInv;
                        vInv.push_back(CInv(MSG_BLOCK, hashBestChain));
                        pfrom->PushMessage("inv", vInv);
                        pfrom->hashContinue = 0;
                    }
                }
            }
            else if (inv.IsKnownType())
            {
                // Send stream from relay memory
                bool pushed = false;
                {
                    LOCK(cs_mapRelay);
                    map<CInv, CDataStream>::iterator mi = mapRelay.find(inv);
                    if (mi != mapRelay.end()) {
                        pfrom->PushMessage(inv.GetCommand(), (*mi).second);
                        pushed = true;
                    }
                }
                if (!pushed && inv.type == MSG_TX) {
                    LOCK(mempool.cs);
                    if (mempool.exists(inv.hash)) {
                        CTransaction tx = mempool.lookup(inv.hash);
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                        ss.reserve(1000);
                        ss << tx;
                        pfrom->PushMessage("tx", ss);
                        pushed = true;
                    }
                }
                if (!pushed) {
                    vNotFound.push_back(inv);
                }
            }

            // Track requests for our stuff.
            Inventory(inv.hash);

            if (inv.type == MSG_BLOCK || inv.type == MSG_FILTERED_BLOCK)
                break;
        }
    }

    pfrom->vRecvGetData.erase(pfrom->vRecvGetData.begin(), it);

    if (!vNotFound.empty()) {
        // Let the peer know that we didn't find what it asked for, so it doesn't
        // have to wait around forever. Currently only SPV clients actually care
        // about this message: it's needed when they are recursively walking the
        // dependencies of relevant unconfirmed transactions. SPV clients want to
        // do that because they want to know about (and store and rebroadcast and
        // risk analyze) the dependencies of transactions relevant to them, without
        // having to download the entire memory pool.
        pfrom->PushMessage("notfound", vNotFound);
    }
}

bool static ProcessMessage(CNode* pfrom, string strCommand, CDataStream& vRecv)
{
    RandAddSeedPerfmon();
    if (fDebug)
        printf("received: %s (%" PRIszu" bytes)\n", strCommand.c_str(), vRecv.size());
    if (mapArgs.count("-dropmessagestest") && GetRand(atoi(mapArgs["-dropmessagestest"])) == 0)
    {
        printf("dropmessagestest DROPPING RECV MESSAGE\n");
        return true;
    }





    if (strCommand == "version")
    {
        // Each connection can only send one version message
        if (pfrom->nVersion != 0)
        {
            pfrom->Misbehaving(1);
            return false;
        }

        int64 nTime;
        CAddress addrMe;
        CAddress addrFrom;
        uint64 nNonce = 1;
        vRecv >> pfrom->nVersion >> pfrom->nServices >> nTime >> addrMe;
        if (pfrom->nVersion < MIN_PEER_PROTO_VERSION)
        {
            // disconnect from peers older than this proto version
            printf("partner %s using obsolete version %i; disconnecting\n", pfrom->addr.ToString().c_str(), pfrom->nVersion);
            pfrom->fDisconnect = true;
            return false;
        }

        if (pfrom->nVersion == 10300)
            pfrom->nVersion = 300;
        if (!vRecv.empty())
            vRecv >> addrFrom >> nNonce;
        if (!vRecv.empty()) {
            vRecv >> pfrom->strSubVer;
            pfrom->cleanSubVer = SanitizeString(pfrom->strSubVer);
        }
        if (!vRecv.empty())
            vRecv >> pfrom->nStartingHeight;
        if (!vRecv.empty())
            vRecv >> pfrom->fRelayTxes; // set to true after we get the first filter* message
        else
            pfrom->fRelayTxes = true;

        if (pfrom->fInbound && addrMe.IsRoutable())
        {
            pfrom->addrLocal = addrMe;
            SeenLocal(addrMe);
        }

        // Disconnect if we connected to ourself
        if (nNonce == nLocalHostNonce && nNonce > 1)
        {
            printf("connected to self at %s, disconnecting\n", pfrom->addr.ToString().c_str());
            pfrom->fDisconnect = true;
            return true;
        }

        // Be shy and don't send version until we hear
        if (pfrom->fInbound)
            pfrom->PushVersion();

        pfrom->fClient = !(pfrom->nServices & NODE_NETWORK);

        AddTimeData(pfrom->addr, nTime);

        // Change version
        pfrom->PushMessage("verack");
        pfrom->ssSend.SetVersion(min(pfrom->nVersion, PROTOCOL_VERSION));

        if (!pfrom->fInbound)
        {
            // Advertise our address
            if (!fNoListen && !IsInitialBlockDownload())
            {
                CAddress addr = GetLocalAddress(&pfrom->addr);
                if (addr.IsRoutable())
                    pfrom->PushAddress(addr);
            }

            // Get recent addresses
            if (pfrom->fOneShot || pfrom->nVersion >= CADDR_TIME_VERSION || addrman.size() < 1000)
            {
                pfrom->PushMessage("getaddr");
                pfrom->fGetAddr = true;
            }
            addrman.Good(pfrom->addr);
        } else {
            if (((CNetAddr)pfrom->addr) == (CNetAddr)addrFrom)
            {
                addrman.Add(addrFrom, addrFrom);
                addrman.Good(addrFrom);
            }
        }

        // Relay alerts
        {
            LOCK(cs_mapAlerts);
            BOOST_FOREACH(PAIRTYPE(const uint256, CAlert)& item, mapAlerts)
                item.second.RelayTo(pfrom);
        }

        pfrom->fSuccessfullyConnected = true;

        printf("receive version message: %s: version %d, blocks=%d, us=%s, them=%s, peer=%s\n", pfrom->cleanSubVer.c_str(), pfrom->nVersion, pfrom->nStartingHeight, addrMe.ToString().c_str(), addrFrom.ToString().c_str(), pfrom->addr.ToString().c_str());

        cPeerBlockCounts.input(pfrom->nStartingHeight);
    }


    else if (pfrom->nVersion == 0)
    {
        // Must have a version message before anything else
        pfrom->Misbehaving(1);
        return false;
    }


    else if (strCommand == "verack")
    {
        pfrom->SetRecvVersion(min(pfrom->nVersion, PROTOCOL_VERSION));
    }


    else if (strCommand == "addr")
    {
        vector<CAddress> vAddr;
        vRecv >> vAddr;

        // Don't want addr from older versions unless seeding
        if (pfrom->nVersion < CADDR_TIME_VERSION && addrman.size() > 1000)
            return true;
        if (vAddr.size() > 1000)
        {
            pfrom->Misbehaving(20);
            return error("message addr size() = %" PRIszu"", vAddr.size());
        }

        // Store the new addresses
        vector<CAddress> vAddrOk;
        int64 nNow = GetAdjustedTime();
        int64 nSince = nNow - 10 * 60;
        BOOST_FOREACH(CAddress& addr, vAddr)
        {
            boost::this_thread::interruption_point();

            if (addr.nTime <= 100000000 || addr.nTime > nNow + 10 * 60)
                addr.nTime = nNow - 5 * 24 * 60 * 60;
            pfrom->AddAddressKnown(addr);
            bool fReachable = IsReachable(addr);
            if (addr.nTime > nSince && !pfrom->fGetAddr && vAddr.size() <= 10 && addr.IsRoutable())
            {
                // Relay to a limited number of other nodes
                {
                    LOCK(cs_vNodes);
                    // Use deterministic randomness to send to the same nodes for 24 hours
                    // at a time so the setAddrKnowns of the chosen nodes prevent repeats
                    static uint256 hashSalt;
                    if (hashSalt == 0)
                        hashSalt = GetRandHash();
                    uint64 hashAddr = addr.GetHash();
                    uint256 hashRand = hashSalt ^ (hashAddr<<32) ^ ((GetTime()+hashAddr)/(24*60*60));
                    hashRand = Hash(BEGIN(hashRand), END(hashRand));
                    multimap<uint256, CNode*> mapMix;
                    BOOST_FOREACH(CNode* pnode, vNodes)
                    {
                        if (pnode->nVersion < CADDR_TIME_VERSION)
                            continue;
                        unsigned int nPointer;
                        memcpy(&nPointer, &pnode, sizeof(nPointer));
                        uint256 hashKey = hashRand ^ nPointer;
                        hashKey = Hash(BEGIN(hashKey), END(hashKey));
                        mapMix.insert(make_pair(hashKey, pnode));
                    }
                    int nRelayNodes = fReachable ? 2 : 1; // limited relaying of addresses outside our network(s)
                    for (multimap<uint256, CNode*>::iterator mi = mapMix.begin(); mi != mapMix.end() && nRelayNodes-- > 0; ++mi)
                        ((*mi).second)->PushAddress(addr);
                }
            }
            // Do not store addresses outside our network
            if (fReachable)
                vAddrOk.push_back(addr);
        }
        addrman.Add(vAddrOk, pfrom->addr, 2 * 60 * 60);
        if (vAddr.size() < 1000)
            pfrom->fGetAddr = false;
        if (pfrom->fOneShot)
            pfrom->fDisconnect = true;
    }


    else if (strCommand == "inv")
    {
        vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() > MAX_INV_SZ)
        {
            pfrom->Misbehaving(20);
            return error("message inv size() = %" PRIszu"", vInv.size());
        }

        // find last block in inv vector
        unsigned int nLastBlock = (unsigned int)(-1);
        for (unsigned int nInv = 0; nInv < vInv.size(); nInv++) {
            if (vInv[vInv.size() - 1 - nInv].type == MSG_BLOCK) {
                nLastBlock = vInv.size() - 1 - nInv;
                break;
            }
        }
        for (unsigned int nInv = 0; nInv < vInv.size(); nInv++)
        {
            const CInv &inv = vInv[nInv];

            boost::this_thread::interruption_point();
            pfrom->AddInventoryKnown(inv);

            bool fAlreadyHave = AlreadyHave(inv);
            if (fDebug)
                printf("  got inventory: %s  %s\n", inv.ToString().c_str(), fAlreadyHave ? "have" : "new");

            if (!fAlreadyHave) {
                if (!fImporting && !fReindex)
                    pfrom->AskFor(inv);
            } else if (inv.type == MSG_BLOCK && mapOrphanBlocks.count(inv.hash)) {
                pfrom->PushGetBlocks(pindexBest, GetOrphanRoot(mapOrphanBlocks[inv.hash]));
            } else if (nInv == nLastBlock) {
                // In case we are on a very long side-chain, it is possible that we already have
                // the last block in an inv bundle sent in response to getblocks. Try to detect
                // this situation and push another getblocks to continue.
                pfrom->PushGetBlocks(mapBlockIndex[inv.hash], uint256(0));
                if (fDebug)
                    printf("force request: %s\n", inv.ToString().c_str());
            }

            // Track requests for our stuff
            Inventory(inv.hash);
        }
    }


    else if (strCommand == "getdata")
    {
        vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() > MAX_INV_SZ)
        {
            pfrom->Misbehaving(20);
            return error("message getdata size() = %" PRIszu"", vInv.size());
        }

        if (fDebugNet || (vInv.size() != 1))
            printf("received getdata (%" PRIszu" invsz)\n", vInv.size());

        if ((fDebugNet && vInv.size() > 0) || (vInv.size() == 1))
            printf("received getdata for: %s\n", vInv[0].ToString().c_str());

        pfrom->vRecvGetData.insert(pfrom->vRecvGetData.end(), vInv.begin(), vInv.end());
        ProcessGetData(pfrom);
    }


    else if (strCommand == "getblocks")
    {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        // Find the last block the caller has in the main chain
        CBlockIndex* pindex = locator.GetBlockIndex();

        // Send the rest of the chain
        if (pindex)
            pindex = pindex->pnext;
        int nLimit = 500;
        printf("getblocks %d to %s limit %d\n", (pindex ? pindex->nHeight : -1), hashStop.ToString().c_str(), nLimit);
        for (; pindex; pindex = pindex->pnext)
        {
            if (pindex->GetBlockHash() == hashStop)
            {
                printf("  getblocks stopping at %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString().c_str());
                break;
            }
            pfrom->PushInventory(CInv(MSG_BLOCK, pindex->GetBlockHash()));
            if (--nLimit <= 0)
            {
                // When this block is requested, we'll send an inv that'll make them
                // getblocks the next batch of inventory.
                printf("  getblocks stopping at limit %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString().c_str());
                pfrom->hashContinue = pindex->GetBlockHash();
                break;
            }
        }
    }


    else if (strCommand == "getheaders")
    {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        CBlockIndex* pindex = NULL;
        if (locator.IsNull())
        {
            // If locator is null, return the hashStop block
            map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashStop);
            if (mi == mapBlockIndex.end())
                return true;
            pindex = (*mi).second;
        }
        else
        {
            // Find the last block the caller has in the main chain
            pindex = locator.GetBlockIndex();
            if (pindex)
                pindex = pindex->pnext;
        }

        // we must use CBlocks, as CBlockHeaders won't include the 0x00 nTx count at the end
        vector<CBlock> vHeaders;
        int nLimit = 2000;
        printf("getheaders %d to %s\n", (pindex ? pindex->nHeight : -1), hashStop.ToString().c_str());
        for (; pindex; pindex = pindex->pnext)
        {
            vHeaders.push_back(pindex->GetBlockHeader());
            if (--nLimit <= 0 || pindex->GetBlockHash() == hashStop)
                break;
        }
        pfrom->PushMessage("headers", vHeaders);
    }


    else if (strCommand == "tx")
    {
        vector<uint256> vWorkQueue;
        vector<uint256> vEraseQueue;
        CDataStream vMsg(vRecv);
        CTransaction tx;
        vRecv >> tx;

        CInv inv(MSG_TX, tx.GetHash());
        pfrom->AddInventoryKnown(inv);

        bool fMissingInputs = false;
        CValidationState state;
        if (tx.AcceptToMemoryPool(state, true, true, &fMissingInputs))
        {
            RelayTransaction(tx, inv.hash);
            mapAlreadyAskedFor.erase(inv);
            vWorkQueue.push_back(inv.hash);
            vEraseQueue.push_back(inv.hash);

            printf("AcceptToMemoryPool: %s %s : accepted %s (poolsz %" PRIszu")\n",
                pfrom->addr.ToString().c_str(), pfrom->cleanSubVer.c_str(),
                tx.GetHash().ToString().c_str(),
                mempool.mapTx.size());

            // Recursively process any orphan transactions that depended on this one
            for (unsigned int i = 0; i < vWorkQueue.size(); i++)
            {
                uint256 hashPrev = vWorkQueue[i];
                for (set<uint256>::iterator mi = mapOrphanTransactionsByPrev[hashPrev].begin();
                     mi != mapOrphanTransactionsByPrev[hashPrev].end();
                     ++mi)
                {
                    const uint256& orphanHash = *mi;
                    const CTransaction& orphanTx = mapOrphanTransactions[orphanHash];
                    bool fMissingInputs2 = false;
                    // Use a dummy CValidationState so someone can't setup nodes to counter-DoS based on orphan
                    // resolution (that is, feeding people an invalid transaction based on LegitTxX in order to get
                    // anyone relaying LegitTxX banned)
                    CValidationState stateDummy;

                    if (tx.AcceptToMemoryPool(stateDummy, true, true, &fMissingInputs2))
                    {
                        printf("   accepted orphan tx %s\n", orphanHash.ToString().c_str());
                        RelayTransaction(orphanTx, orphanHash);
                        mapAlreadyAskedFor.erase(CInv(MSG_TX, orphanHash));
                        vWorkQueue.push_back(orphanHash);
                        vEraseQueue.push_back(orphanHash);
                    }
                    else if (!fMissingInputs2)
                    {
                        // invalid or too-little-fee orphan
                        vEraseQueue.push_back(orphanHash);
                        printf("   removed orphan tx %s\n", orphanHash.ToString().c_str());
                    }
                }
            }

            BOOST_FOREACH(uint256 hash, vEraseQueue)
                EraseOrphanTx(hash);
        }
        else if (fMissingInputs)
        {
            AddOrphanTx(tx);

            // DoS prevention: do not allow mapOrphanTransactions to grow unbounded
            unsigned int nEvicted = LimitOrphanTxSize(MAX_ORPHAN_TRANSACTIONS);
            if (nEvicted > 0)
                printf("mapOrphan overflow, removed %u tx\n", nEvicted);
        }
        int nDoS = 0;
        if (state.IsInvalid(nDoS))
        {
            printf("%s from %s %s was not accepted into the memory pool\n", tx.GetHash().ToString().c_str(),
                pfrom->addr.ToString().c_str(), pfrom->cleanSubVer.c_str());
            if (nDoS > 0)
                pfrom->Misbehaving(nDoS);
        }
    }


    else if (strCommand == "block" && !fImporting && !fReindex) // Ignore blocks received while importing
    {
        CBlock block;
        vRecv >> block;

        printf("received block %s\n", block.GetHash().ToString().c_str());
        // block.print();

        CInv inv(MSG_BLOCK, block.GetHash());
        pfrom->AddInventoryKnown(inv);

        CValidationState state;
        if (ProcessBlock(state, pfrom, &block) || state.CorruptionPossible())
            mapAlreadyAskedFor.erase(inv);
        int nDoS = 0;
        if (state.IsInvalid(nDoS))
            if (nDoS > 0)
                pfrom->Misbehaving(nDoS);
    }


    else if (strCommand == "getaddr")
    {
        pfrom->vAddrToSend.clear();
        vector<CAddress> vAddr = addrman.GetAddr();
        BOOST_FOREACH(const CAddress &addr, vAddr)
            pfrom->PushAddress(addr);
    }


    else if (strCommand == "mempool")
    {
        std::vector<uint256> vtxid;
        LOCK2(mempool.cs, pfrom->cs_filter);
        mempool.queryHashes(vtxid);
        vector<CInv> vInv;
        BOOST_FOREACH(uint256& hash, vtxid) {
            CInv inv(MSG_TX, hash);
            if ((pfrom->pfilter && pfrom->pfilter->IsRelevantAndUpdate(mempool.lookup(hash), hash)) ||
               (!pfrom->pfilter))
                vInv.push_back(inv);
            if (vInv.size() == MAX_INV_SZ)
                break;
        }
        if (vInv.size() > 0)
            pfrom->PushMessage("inv", vInv);
    }


    else if (strCommand == "ping")
    {
        if (pfrom->nVersion > BIP0031_VERSION)
        {
            uint64 nonce = 0;
            vRecv >> nonce;
            // Echo the message back with the nonce. This allows for two useful features:
            //
            // 1) A remote node can quickly check if the connection is operational
            // 2) Remote nodes can measure the latency of the network thread. If this node
            //    is overloaded it won't respond to pings quickly and the remote node can
            //    avoid sending us more work, like chain download requests.
            //
            // The nonce stops the remote getting confused between different pings: without
            // it, if the remote node sends a ping once per second and this node takes 5
            // seconds to respond to each, the 5th ping the remote sends would appear to
            // return very quickly.
            pfrom->PushMessage("pong", nonce);
        }
    }


    else if (strCommand == "alert")
    {
        CAlert alert;
        vRecv >> alert;

        uint256 alertHash = alert.GetHash();
        if (pfrom->setKnown.count(alertHash) == 0)
        {
            if (alert.ProcessAlert())
            {
                // Relay
                pfrom->setKnown.insert(alertHash);
                {
                    LOCK(cs_vNodes);
                    BOOST_FOREACH(CNode* pnode, vNodes)
                        alert.RelayTo(pnode);
                }
            }
            else {
                // Small DoS penalty so peers that send us lots of
                // duplicate/expired/invalid-signature/whatever alerts
                // eventually get banned.
                // This isn't a Misbehaving(100) (immediate ban) because the
                // peer might be an older or different implementation with
                // a different signature key, etc.
                pfrom->Misbehaving(10);
            }
        }
    }


    else if (!fBloomFilters &&
             (strCommand == "filterload" ||
              strCommand == "filteradd" ||
              strCommand == "filterclear"))
    {
        pfrom->CloseSocketDisconnect();
        return error("peer %s attempted to set a bloom filter even though we do not advertise that service",
                     pfrom->addr.ToString().c_str());
    }

    else if (strCommand == "filterload")
    {
        CBloomFilter filter;
        vRecv >> filter;

        if (!filter.IsWithinSizeConstraints())
            // There is no excuse for sending a too-large filter
            pfrom->Misbehaving(100);
        else
        {
            LOCK(pfrom->cs_filter);
            delete pfrom->pfilter;
            pfrom->pfilter = new CBloomFilter(filter);
            pfrom->pfilter->UpdateEmptyFull();
        }
        pfrom->fRelayTxes = true;
    }


    else if (strCommand == "filteradd")
    {
        vector<unsigned char> vData;
        vRecv >> vData;

        // Nodes must NEVER send a data item > 520 bytes (the max size for a script data object,
        // and thus, the maximum size any matched object can have) in a filteradd message
        if (vData.size() > MAX_SCRIPT_ELEMENT_SIZE)
        {
            pfrom->Misbehaving(100);
        } else {
            LOCK(pfrom->cs_filter);
            if (pfrom->pfilter)
                pfrom->pfilter->insert(vData);
            else
                pfrom->Misbehaving(100);
        }
    }


    else if (strCommand == "filterclear")
    {
        LOCK(pfrom->cs_filter);
        delete pfrom->pfilter;
        pfrom->pfilter = new CBloomFilter();
        pfrom->fRelayTxes = true;
    }


    else
    {
        // Ignore unknown commands for extensibility
    }


    // Update the last seen time for this node's address
    if (pfrom->fNetworkNode)
        if (strCommand == "version" || strCommand == "addr" || strCommand == "inv" || strCommand == "getdata" || strCommand == "ping")
            AddressCurrentlyConnected(pfrom->addr);


    return true;
}

// requires LOCK(cs_vRecvMsg)
bool ProcessMessages(CNode* pfrom)
{
    //if (fDebug)
    //    printf("ProcessMessages(%zu messages)\n", pfrom->vRecvMsg.size());

    //
    // Message format
    //  (4) message start
    //  (12) command
    //  (4) size
    //  (4) checksum
    //  (x) data
    //
    bool fOk = true;

    if (!pfrom->vRecvGetData.empty())
        ProcessGetData(pfrom);

    // this maintains the order of responses
    if (!pfrom->vRecvGetData.empty()) return fOk;

    std::deque<CNetMessage>::iterator it = pfrom->vRecvMsg.begin();
    while (!pfrom->fDisconnect && it != pfrom->vRecvMsg.end()) {
        // Don't bother if send buffer is too full to respond anyway
        if (pfrom->nSendSize >= SendBufferSize())
            break;

        // get next message
        CNetMessage& msg = *it;

        //if (fDebug)
        //    printf("ProcessMessages(message %u msgsz, %zu bytes, complete:%s)\n",
        //            msg.hdr.nMessageSize, msg.vRecv.size(),
        //            msg.complete() ? "Y" : "N");

        // end, if an incomplete message is found
        if (!msg.complete())
            break;

        // at this point, any failure means we can delete the current message
        it++;

        // Scan for message start
        if (memcmp(msg.hdr.pchMessageStart, pchMessageStart, sizeof(pchMessageStart)) != 0) {
            printf("\n\nPROCESSMESSAGE: INVALID MESSAGESTART\n\n");
            fOk = false;
            break;
        }

        // Read header
        CMessageHeader& hdr = msg.hdr;
        if (!hdr.IsValid())
        {
            printf("\n\nPROCESSMESSAGE: ERRORS IN HEADER %s\n\n\n", hdr.GetCommand().c_str());
            continue;
        }
        string strCommand = hdr.GetCommand();

        // Message size
        unsigned int nMessageSize = hdr.nMessageSize;

        // Checksum
        CDataStream& vRecv = msg.vRecv;
        uint256 hash = Hash(vRecv.begin(), vRecv.begin() + nMessageSize);
        unsigned int nChecksum = 0;
        memcpy(&nChecksum, &hash, sizeof(nChecksum));
        if (nChecksum != hdr.nChecksum)
        {
            printf("ProcessMessages(%s, %u bytes) : CHECKSUM ERROR nChecksum=%08x hdr.nChecksum=%08x\n",
               strCommand.c_str(), nMessageSize, nChecksum, hdr.nChecksum);
            continue;
        }

        // Process message
        bool fRet = false;
        try
        {
            {
                LOCK(cs_main);
                fRet = ProcessMessage(pfrom, strCommand, vRecv);
            }
            boost::this_thread::interruption_point();
        }
        catch (std::ios_base::failure& e)
        {
            if (strstr(e.what(), "end of data"))
            {
                // Allow exceptions from under-length message on vRecv
                printf("ProcessMessages(%s, %u bytes) : Exception '%s' caught, normally caused by a message being shorter than its stated length\n", strCommand.c_str(), nMessageSize, e.what());
            }
            else if (strstr(e.what(), "size too large"))
            {
                // Allow exceptions from over-long size
                printf("ProcessMessages(%s, %u bytes) : Exception '%s' caught\n", strCommand.c_str(), nMessageSize, e.what());
            }
            else
            {
                PrintExceptionContinue(&e, "ProcessMessages()");
            }
        }
        catch (boost::thread_interrupted) {
            throw;
        }
        catch (std::exception& e) {
            PrintExceptionContinue(&e, "ProcessMessages()");
        } catch (...) {
            PrintExceptionContinue(NULL, "ProcessMessages()");
        }

        if (!fRet)
            printf("ProcessMessage(%s, %u bytes) FAILED\n", strCommand.c_str(), nMessageSize);

        break;
    }

    // In case the connection got shut down, its receive buffer was wiped
    if (!pfrom->fDisconnect)
        pfrom->vRecvMsg.erase(pfrom->vRecvMsg.begin(), it);

    return fOk;
}


bool SendMessages(CNode* pto, bool fSendTrickle)
{
    TRY_LOCK(cs_main, lockMain);
    if (lockMain) {
        // Don't send anything until we get their version message
        if (pto->nVersion == 0)
            return true;

        // Keep-alive ping. We send a nonce of zero because we don't use it anywhere
        // right now.
        if (pto->nLastSend && GetTime() - pto->nLastSend > 30 * 60 && pto->vSendMsg.empty()) {
            uint64 nonce = 0;
            if (pto->nVersion > BIP0031_VERSION)
                pto->PushMessage("ping", nonce);
            else
                pto->PushMessage("ping");
        }

        // Start block sync
        if (pto->fStartSync && !fImporting && !fReindex) {
            pto->fStartSync = false;
            pto->PushGetBlocks(pindexBest, uint256(0));
        }

        // Resend wallet transactions that haven't gotten in a block yet
        // Except during reindex, importing and IBD, when old wallet
        // transactions become unconfirmed and spams other nodes.
        if (!fReindex && !fImporting && !IsInitialBlockDownload())
        {
            ResendWalletTransactions();
        }

        // Address refresh broadcast
        static int64 nLastRebroadcast;
        if (!IsInitialBlockDownload() && (GetTime() - nLastRebroadcast > 24 * 60 * 60))
        {
            {
                LOCK(cs_vNodes);
                BOOST_FOREACH(CNode* pnode, vNodes)
                {
                    // Periodically clear setAddrKnown to allow refresh broadcasts
                    if (nLastRebroadcast)
                        pnode->setAddrKnown.clear();

                    // Rebroadcast our address
                    if (!fNoListen)
                    {
                        CAddress addr = GetLocalAddress(&pnode->addr);
                        if (addr.IsRoutable())
                            pnode->PushAddress(addr);
                    }
                }
            }
            nLastRebroadcast = GetTime();
        }

        //
        // Message: addr
        //
        if (fSendTrickle)
        {
            vector<CAddress> vAddr;
            vAddr.reserve(pto->vAddrToSend.size());
            BOOST_FOREACH(const CAddress& addr, pto->vAddrToSend)
            {
                // returns true if wasn't already contained in the set
                if (pto->setAddrKnown.insert(addr).second)
                {
                    vAddr.push_back(addr);
                    // receiver rejects addr messages larger than 1000
                    if (vAddr.size() >= 1000)
                    {
                        pto->PushMessage("addr", vAddr);
                        vAddr.clear();
                    }
                }
            }
            pto->vAddrToSend.clear();
            if (!vAddr.empty())
                pto->PushMessage("addr", vAddr);
        }


        //
        // Message: inventory
        //
        vector<CInv> vInv;
        vector<CInv> vInvWait;
        {
            LOCK(pto->cs_inventory);
            vInv.reserve(pto->vInventoryToSend.size());
            vInvWait.reserve(pto->vInventoryToSend.size());
            BOOST_FOREACH(const CInv& inv, pto->vInventoryToSend)
            {
                if (pto->setInventoryKnown.count(inv))
                    continue;

                // trickle out tx inv to protect privacy
                if (inv.type == MSG_TX && !fSendTrickle)
                {
                    // 1/4 of tx invs blast to all immediately
                    static uint256 hashSalt;
                    if (hashSalt == 0)
                        hashSalt = GetRandHash();
                    uint256 hashRand = inv.hash ^ hashSalt;
                    hashRand = Hash(BEGIN(hashRand), END(hashRand));
                    bool fTrickleWait = ((hashRand & 3) != 0);

                    // always trickle our own transactions
                    if (!fTrickleWait)
                    {
                        CWalletTx wtx;
                        if (GetTransaction(inv.hash, wtx))
                            if (wtx.fFromMe)
                                fTrickleWait = true;
                    }

                    if (fTrickleWait)
                    {
                        vInvWait.push_back(inv);
                        continue;
                    }
                }

                // returns true if wasn't already contained in the set
                if (pto->setInventoryKnown.insert(inv).second)
                {
                    vInv.push_back(inv);
                    if (vInv.size() >= 1000)
                    {
                        pto->PushMessage("inv", vInv);
                        vInv.clear();
                    }
                }
            }
            pto->vInventoryToSend = vInvWait;
        }
        if (!vInv.empty())
            pto->PushMessage("inv", vInv);


        //
        // Message: getdata
        //
        vector<CInv> vGetData;
        int64 nNow = GetTime() * 1000000;
        while (!pto->mapAskFor.empty() && (*pto->mapAskFor.begin()).first <= nNow)
        {
            const CInv& inv = (*pto->mapAskFor.begin()).second;
            if (!AlreadyHave(inv))
            {
                if (fDebugNet)
                    printf("sending getdata: %s\n", inv.ToString().c_str());
                vGetData.push_back(inv);
                if (vGetData.size() >= 1000)
                {
                    pto->PushMessage("getdata", vGetData);
                    vGetData.clear();
                }
            }
            pto->mapAskFor.erase(pto->mapAskFor.begin());
        }
        if (!vGetData.empty())
            pto->PushMessage("getdata", vGetData);

    }
    return true;
}














//////////////////////////////////////////////////////////////////////////////
//
// CryptoMiner
//

int static FormatHashBlocks(void* pbuffer, unsigned int len)
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

static const unsigned int pSHA256InitState[8] =
{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

void SHA256Transform(void* pstate, void* pinput, const void* pinit)
{
    SHA256_CTX ctx;
    unsigned char data[64];

    SHA256_Init(&ctx);

    for (int i = 0; i < 16; i++)
        ((uint32_t*)data)[i] = ByteReverse(((uint32_t*)pinput)[i]);

    for (int i = 0; i < 8; i++)
        ctx.h[i] = ((uint32_t*)pinit)[i];

    SHA256_Update(&ctx, data, sizeof(data));
    for (int i = 0; i < 8; i++)
        ((uint32_t*)pstate)[i] = ctx.h[i];
}

// Some explaining would be appreciated
class COrphan
{
public:
    CTransaction* ptx;
    set<uint256> setDependsOn;
    double dPriority;
    double dFeePerKb;

    COrphan(CTransaction* ptxIn)
    {
        ptx = ptxIn;
        dPriority = dFeePerKb = 0;
    }

    void print() const
    {
        printf("COrphan(hash=%s, dPriority=%.1f, dFeePerKb=%.1f)\n",
               ptx->GetHash().ToString().c_str(), dPriority, dFeePerKb);
        BOOST_FOREACH(uint256 hash, setDependsOn)
            printf("   setDependsOn %s\n", hash.ToString().c_str());
    }
};


uint64 nLastBlockTx = 0;
uint64 nLastBlockSize = 0;

// We want to sort transactions by priority and fee, so:
typedef boost::tuple<double, double, CTransaction*> TxPriority;
class TxPriorityCompare
{
    bool byFee;
public:
    TxPriorityCompare(bool _byFee) : byFee(_byFee) { }
    bool operator()(const TxPriority& a, const TxPriority& b)
    {
        if (byFee)
        {
            if (a.get<1>() == b.get<1>())
                return a.get<0>() < b.get<0>();
            return a.get<1>() < b.get<1>();
        }
        else
        {
            if (a.get<0>() == b.get<0>())
                return a.get<1>() < b.get<1>();
            return a.get<0>() < b.get<0>();
        }
    }
};

CBlockTemplate* CreateNewBlock(const CScript& scriptPubKeyIn)
{
    // Create new block
    auto_ptr<CBlockTemplate> pblocktemplate(new CBlockTemplate());
    if(!pblocktemplate.get())
        return NULL;
    CBlock *pblock = &pblocktemplate->block; // pointer for convenience

    // Create coinbase tx
    CTransaction txNew;
    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetNull();
    txNew.vout.resize(1);
    txNew.vout[0].scriptPubKey = scriptPubKeyIn;

    // Add our coinbase tx as first transaction
    pblock->vtx.push_back(txNew);
    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOps.push_back(-1); // updated at end

    // Largest block you're willing to create:
    unsigned int nBlockMaxSize = GetArg("-blockmaxsize", DEFAULT_BLOCK_MAX_SIZE);
    // Limit to betweeen 1K and MAX_BLOCK_SIZE-1K for sanity:
    nBlockMaxSize = std::max((unsigned int)1000, std::min((unsigned int)(MAX_BLOCK_SIZE-1000), nBlockMaxSize));

    // How much of the block should be dedicated to high-priority transactions,
    // included regardless of the fees they pay
    unsigned int nBlockPrioritySize = GetArg("-blockprioritysize", DEFAULT_BLOCK_PRIORITY_SIZE);
    nBlockPrioritySize = std::min(nBlockMaxSize, nBlockPrioritySize);

    // Minimum block size you want to create; block will be filled with free transactions
    // until there are no more or the block reaches this size:
    unsigned int nBlockMinSize = GetArg("-blockminsize", 0);
    nBlockMinSize = std::min(nBlockMaxSize, nBlockMinSize);

    // Collect memory pool transactions into the block
    int64 nFees = 0;
    {
        LOCK2(cs_main, mempool.cs);
        CBlockIndex* pindexPrev = pindexBest;
        CCoinsViewCache view(*pcoinsTip, true);

        // Priority order to process transactions
        list<COrphan> vOrphan; // list memory doesn't move
        map<uint256, vector<COrphan*> > mapDependers;
        bool fPrintPriority = GetBoolArg("-printpriority");

        // This vector will be sorted into a priority queue:
        vector<TxPriority> vecPriority;
        vecPriority.reserve(mempool.mapTx.size());
        for (map<uint256, CTransaction>::iterator mi = mempool.mapTx.begin(); mi != mempool.mapTx.end(); ++mi)
        {
            CTransaction& tx = (*mi).second;
            if (tx.IsCoinBase() || !tx.IsFinal())
                continue;

            COrphan* porphan = NULL;
            double dPriority = 0;
            int64 nTotalIn = 0;
            bool fMissingInputs = false;
            BOOST_FOREACH(const CTxIn& txin, tx.vin)
            {
                // Read prev transaction
                if (!view.HaveCoins(txin.prevout.hash))
                {
                    // This should never happen; all transactions in the memory
                    // pool should connect to either transactions in the chain
                    // or other transactions in the memory pool.
                    if (!mempool.mapTx.count(txin.prevout.hash))
                    {
                        printf("ERROR: mempool transaction missing input\n");
                        if (fDebug) assert("mempool transaction missing input" == 0);
                        fMissingInputs = true;
                        if (porphan)
                            vOrphan.pop_back();
                        break;
                    }

                    // Has to wait for dependencies
                    if (!porphan)
                    {
                        // Use list for automatic deletion
                        vOrphan.push_back(COrphan(&tx));
                        porphan = &vOrphan.back();
                    }
                    mapDependers[txin.prevout.hash].push_back(porphan);
                    porphan->setDependsOn.insert(txin.prevout.hash);
                    nTotalIn += mempool.mapTx[txin.prevout.hash].vout[txin.prevout.n].nValue;
                    continue;
                }
                const CCoins &coins = view.GetCoins(txin.prevout.hash);

                int64 nValueIn = coins.vout[txin.prevout.n].nValue;
                nTotalIn += nValueIn;

                int nConf = pindexPrev->nHeight - coins.nHeight + 1;

                dPriority += (double)nValueIn * nConf;
            }
            if (fMissingInputs) continue;

            // Priority is sum(valuein * age) / txsize
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            dPriority /= nTxSize;

            // This is a more accurate fee-per-kilobyte than is used by the client code, because the
            // client code rounds up the size to the nearest 1K. That's good, because it gives an
            // incentive to create smaller transactions.
            double dFeePerKb =  double(nTotalIn-tx.GetValueOut()) / (double(nTxSize)/1000.0);

            if (porphan)
            {
                porphan->dPriority = dPriority;
                porphan->dFeePerKb = dFeePerKb;
            }
            else
                vecPriority.push_back(TxPriority(dPriority, dFeePerKb, &(*mi).second));
        }

        // Collect transactions into block
        uint64 nBlockSize = 1000;
        uint64 nBlockTx = 0;
        int nBlockSigOps = 100;
        bool fSortedByFee = (nBlockPrioritySize <= 0);

        TxPriorityCompare comparer(fSortedByFee);
        std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);

        while (!vecPriority.empty())
        {
            // Take highest priority transaction off the priority queue:
            double dPriority = vecPriority.front().get<0>();
            double dFeePerKb = vecPriority.front().get<1>();
            CTransaction& tx = *(vecPriority.front().get<2>());

            std::pop_heap(vecPriority.begin(), vecPriority.end(), comparer);
            vecPriority.pop_back();

            // Size limits
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            if (nBlockSize + nTxSize >= nBlockMaxSize)
                continue;

            // Legacy limits on sigOps:
            unsigned int nTxSigOps = tx.GetLegacySigOpCount();
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
                continue;

            // Skip free transactions if we're past the minimum block size:
            if (fSortedByFee && (dFeePerKb < CTransaction::nMinTxFee) && (nBlockSize + nTxSize >= nBlockMinSize))
                continue;

            // Prioritize by fee once past the priority size or we run out of high-priority
            // transactions:
            if (!fSortedByFee &&
                ((nBlockSize + nTxSize >= nBlockPrioritySize) || (dPriority < COIN * 576 / 250)))
            {
                fSortedByFee = true;
                comparer = TxPriorityCompare(fSortedByFee);
                std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);
            }

            if (!tx.HaveInputs(view))
                continue;

            int64 nTxFees = tx.GetValueIn(view)-tx.GetValueOut();

            nTxSigOps += tx.GetP2SHSigOpCount(view);
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
                continue;

            CValidationState state;
            if (!tx.CheckInputs(state, view, true, SCRIPT_VERIFY_P2SH))
                continue;

            CTxUndo txundo;
            uint256 hash = tx.GetHash();
            tx.UpdateCoins(state, view, txundo, pindexPrev->nHeight+1, hash);

            // Added
            pblock->vtx.push_back(tx);
            pblocktemplate->vTxFees.push_back(nTxFees);
            pblocktemplate->vTxSigOps.push_back(nTxSigOps);
            nBlockSize += nTxSize;
            ++nBlockTx;
            nBlockSigOps += nTxSigOps;
            nFees += nTxFees;

            if (fPrintPriority)
            {
                printf("priority %.1f feeperkb %.1f txid %s\n",
                       dPriority, dFeePerKb, tx.GetHash().ToString().c_str());
            }

            // Add transactions that depend on this one to the priority queue
            if (mapDependers.count(hash))
            {
                BOOST_FOREACH(COrphan* porphan, mapDependers[hash])
                {
                    if (!porphan->setDependsOn.empty())
                    {
                        porphan->setDependsOn.erase(hash);
                        if (porphan->setDependsOn.empty())
                        {
                            vecPriority.push_back(TxPriority(porphan->dPriority, porphan->dFeePerKb, porphan->ptx));
                            std::push_heap(vecPriority.begin(), vecPriority.end(), comparer);
                        }
                    }
                }
            }
        }

        nLastBlockTx = nBlockTx;
        nLastBlockSize = nBlockSize;
        printf("CreateNewBlock(): total size %" PRI64u"\n", nBlockSize);

        pblock->vtx[0].vout[0].nValue = GetBlockValue(pindexPrev->nHeight+1, nFees);
        pblocktemplate->vTxFees[0] = -nFees;

        // Fill in header
        pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
        pblock->LastHeight = pindexPrev->nHeight;
        pblock->UpdateTime(pindexPrev);
        pblock->nBits          = GetNextWorkRequired(pindexPrev, pblock);
        pblock->nNonce         = 0;
        pblock->vtx[0].vin[0].scriptSig = CScript() << OP_0 << OP_0;
        pblocktemplate->vTxSigOps[0] = pblock->vtx[0].GetLegacySigOpCount();

        CBlockIndex indexDummy(*pblock);
        indexDummy.pprev = pindexPrev;
        indexDummy.nHeight = pindexPrev->nHeight + 1;
        CCoinsViewCache viewNew(*pcoinsTip, true);
        CValidationState state;
        if (!pblock->ConnectBlock(state, &indexDummy, viewNew, true))
            throw std::runtime_error("CreateNewBlock() : ConnectBlock failed");
    }

    return pblocktemplate.release();
}

CBlockTemplate* CreateNewBlockWithKey(CReserveKey& reservekey)
{
    CPubKey pubkey;
    if (!reservekey.GetReservedKey(pubkey))
        return NULL;

    CScript scriptPubKey = CScript() << pubkey << OP_CHECKSIG;
    return CreateNewBlock(scriptPubKey);
}

void IncrementExtraNonce(CBlock* pblock, CBlockIndex* pindexPrev, unsigned int& nExtraNonce)
{
    // Update nExtraNonce
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock)
    {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;
    unsigned int nHeight = pindexPrev->nHeight+1; // Height first in coinbase required for block.version=2
    pblock->vtx[0].vin[0].scriptSig = (CScript() << nHeight << CBigNum(nExtraNonce)) + COINBASE_FLAGS;
    assert(pblock->vtx[0].vin[0].scriptSig.size() <= 100);

    pblock->hashMerkleRoot = pblock->BuildMerkleTree();
}


void FormatHashBuffers(CBlock* pblock, char* pmidstate, char* pdata, char* phash1)
{
    //
    // Pre-build hash buffers
    //
    struct
    {
        struct unnamed2
        {
            int nVersion;
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
    memset(&tmp, 0, sizeof(tmp));

    tmp.block.nVersion       = pblock->nVersion;
    tmp.block.hashPrevBlock  = pblock->hashPrevBlock;
    tmp.block.hashMerkleRoot = pblock->hashMerkleRoot;
    tmp.block.nTime          = pblock->nTime;
    tmp.block.nBits          = pblock->nBits;
    tmp.block.nNonce         = pblock->nNonce;

    FormatHashBlocks(&tmp.block, sizeof(tmp.block));
    FormatHashBlocks(&tmp.hash1, sizeof(tmp.hash1));

    // Byte swap all the input buffer
    for (unsigned int i = 0; i < sizeof(tmp)/4; i++)
        ((unsigned int*)&tmp)[i] = ByteReverse(((unsigned int*)&tmp)[i]);

    // Precalc the first half of the first hash, which stays constant
    SHA256Transform(pmidstate, &tmp.block, pSHA256InitState);

    memcpy(pdata, &tmp.block, 128);
    memcpy(phash1, &tmp.hash1, 64);
}


bool CheckWork(CBlock* pblock, CWallet& wallet, CReserveKey& reservekey)
{
    CBlockIndex* pindexPrev = NULL;
    int nHeight = 0;
    if (pblock->GetHash() != hashGenesisBlock)
    {
        map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(pblock->hashPrevBlock);
        pindexPrev = (*mi).second;
        nHeight = pindexPrev->nHeight+1;
    }
    
	uint256 hash = pblock->GetPoWHash(nHeight);
    uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();
    printf("Hash found: %s", hash.GetHex().c_str());

    if (hash > hashTarget)
        return false;

    //// debug print
    printf("CryptoMiner:\n");
    printf("proof-of-work found  \n  hash: %s  \ntarget: %s\n", hash.GetHex().c_str(), hashTarget.GetHex().c_str());
    pblock->print();
    printf("generated %s\n", FormatMoney(pblock->vtx[0].vout[0].nValue).c_str());

    // Found a solution
    {
        LOCK(cs_main);
        if (pblock->hashPrevBlock != hashBestChain)
            return error("CryptoMiner : generated block is stale");

        // Remove key from key pool
        reservekey.KeepKey();

        // Track how many getdata requests this block gets
        {
            LOCK(wallet.cs_wallet);
            wallet.mapRequestCount[pblock->GetHash()] = 0;
        }

        // Process this block the same as if we had received it from another node
        CValidationState state;
        if (!ProcessBlock(state, NULL, pblock))
            return error("CryptoMiner : ProcessBlock, block not accepted");
    }

    return true;
}

void static CryptoMiner(CWallet *pwallet)
{
    printf("CryptoMiner started\n");

    SetThreadPriority(THREAD_PRIORITY_LOWEST);
    RenameThread("crypto-miner");

    // Each thread has its own key and counter
    CReserveKey reservekey(pwallet);
    unsigned int nExtraNonce = 0;

    try { loop {
        while (vNodes.empty())
            MilliSleep(1000);

        //
        // Create new block
        //
        unsigned int nTransactionsUpdatedLast = nTransactionsUpdated;
        CBlockIndex* pindexPrev = pindexBest;

        auto_ptr<CBlockTemplate> pblocktemplate(CreateNewBlockWithKey(reservekey));
        if (!pblocktemplate.get())
            return;
        CBlock *pblock = &pblocktemplate->block;
        IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

        printf("Running CryptoMiner with %" PRIszu" transactions in block (%u bytes)\n", pblock->vtx.size(),
               ::GetSerializeSize(*pblock, SER_NETWORK, PROTOCOL_VERSION));

        //
        // Pre-build hash buffers
        //
        char pmidstatebuf[32+16]; char* pmidstate = alignup<16>(pmidstatebuf);
        char pdatabuf[128+16];    char* pdata     = alignup<16>(pdatabuf);
        char phash1buf[64+16];    char* phash1    = alignup<16>(phash1buf);

        FormatHashBuffers(pblock, pmidstate, pdata, phash1);

        unsigned int& nBlockTime = *(unsigned int*)(pdata + 64 + 4);
        unsigned int& nBlockBits = *(unsigned int*)(pdata + 64 + 8);
        //unsigned int& nBlockNonce = *(unsigned int*)(pdata + 64 + 12);


        //
        // Search
        //
        int64 nStart = GetTime();
        uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();
        loop
        {
            unsigned int nHashesDone = 0;

            uint256 thash;

            unsigned long int scrypt_scratpad_size_current_block = ((1 << (GetNfactor(pblock->nTime) + 1)) * 128 ) + 63;

            char scratchpad[scrypt_scratpad_size_current_block];

            /*printf("nTime -> %d", pblock->nTime);
            printf("scrypt_scratpad_size_current_block -> %ld", sizeof(scrypt_scratpad_size_current_block));
            printf("scratchpad -> %d", sizeof(scratchpad));*/

            loop
            {
                if((fTestNet && pindexPrev->nHeight+1 >= 0) || pindexPrev->nHeight+1 >= 0)
                {
                    lyra2re_hash(BEGIN(pblock->nVersion), BEGIN(thash));
                }
                else
                {
                    scrypt_N_1_1_256_sp_generic(BEGIN(pblock->nVersion), BEGIN(thash), scratchpad, GetNfactor(pblock->nTime));
                }

                if (thash <= hashTarget)
                {
                    // Found a solution
                    printf("Entering to found a solution section. Hash: %s", thash.GetHex().c_str());
                    SetThreadPriority(THREAD_PRIORITY_NORMAL);
                    CheckWork(pblock, *pwallet, reservekey);
                    SetThreadPriority(THREAD_PRIORITY_LOWEST);
                    break;
                }
                pblock->nNonce += 1;
                nHashesDone += 1;
                if ((pblock->nNonce & 0xFF) == 0)
                    break;
            }

            // Meter hashes/sec
            static int64 nHashCounter;
            if (nHPSTimerStart == 0)
            {
                nHPSTimerStart = GetTimeMillis();
                nHashCounter = 0;
            }
            else
                nHashCounter += nHashesDone;
            if (GetTimeMillis() - nHPSTimerStart > 4000)
            {
                static CCriticalSection cs;
                {
                    LOCK(cs);
                    if (GetTimeMillis() - nHPSTimerStart > 4000)
                    {
                        dHashesPerSec = 1000.0 * nHashCounter / (GetTimeMillis() - nHPSTimerStart);
                        nHPSTimerStart = GetTimeMillis();
                        nHashCounter = 0;
                        static int64 nLogTime;
                        if (GetTime() - nLogTime > 30 * 60)
                        {
                            nLogTime = GetTime();
                            printf("hashmeter %6.0f khash/s\n", dHashesPerSec/1000.0);
                        }
                    }
                }
            }

            // Check for stop or if block needs to be rebuilt
            boost::this_thread::interruption_point();
            if (vNodes.empty())
                break;
            if (pblock->nNonce >= 0xffff0000)
                break;
            if (nTransactionsUpdated != nTransactionsUpdatedLast && GetTime() - nStart > 60)
                break;
            if (pindexPrev != pindexBest)
                break;

            // Update nTime every few seconds
            pblock->UpdateTime(pindexPrev);
            nBlockTime = ByteReverse(pblock->nTime);
            if (fTestNet)
            {
                // Changing pblock->nTime can change work required on testnet:
                nBlockBits = ByteReverse(pblock->nBits);
                hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();
            }
        }
    } }
    catch (boost::thread_interrupted)
    {
        printf("CryptoMiner terminated\n");
        throw;
    }
}

void GenerateBitcoins(bool fGenerate, CWallet* pwallet)
{
    static boost::thread_group* minerThreads = NULL;

    int nThreads = GetArg("-genproclimit", -1);
    if (nThreads < 0)
        nThreads = boost::thread::hardware_concurrency();

    if (minerThreads != NULL)
    {
        minerThreads->interrupt_all();
        delete minerThreads;
        minerThreads = NULL;
    }

    if (nThreads == 0 || !fGenerate)
        return;

    minerThreads = new boost::thread_group();
    for (int i = 0; i < nThreads; i++)
        minerThreads->create_thread(boost::bind(&CryptoMiner, pwallet));
}

// Amount compression:
// * If the amount is 0, output 0
// * first, divide the amount (in base units) by the largest power of 10 possible; call the exponent e (e is max 9)
// * if e<9, the last digit of the resulting number cannot be 0; store it as d, and drop it (divide by 10)
//   * call the result n
//   * output 1 + 10*(9*n + d - 1) + e
// * if e==9, we only know the resulting number is not zero, so output 1 + 10*(n - 1) + 9
// (this is decodable, as d is in [1-9] and e is in [0-9])

uint64 CTxOutCompressor::CompressAmount(uint64 n)
{
    if (n == 0)
        return 0;
    int e = 0;
    while (((n % 10) == 0) && e < 9) {
        n /= 10;
        e++;
    }
    if (e < 9) {
        int d = (n % 10);
        assert(d >= 1 && d <= 9);
        n /= 10;
        return 1 + (n*9 + d - 1)*10 + e;
    } else {
        return 1 + (n - 1)*10 + 9;
    }
}

uint64 CTxOutCompressor::DecompressAmount(uint64 x)
{
    // x = 0  OR  x = 1+10*(9*n + d - 1) + e  OR  x = 1+10*(n - 1) + 9
    if (x == 0)
        return 0;
    x--;
    // x = 10*(9*n + d - 1) + e
    int e = x % 10;
    x /= 10;
    uint64 n = 0;
    if (e < 9) {
        // x = 9*n + d - 1
        int d = (x % 9) + 1;
        x /= 9;
        // x = n
        n = x*10 + d;
    } else {
        n = x+1;
    }
    while (e) {
        n *= 10;
        e--;
    }
    return n;
}


class CMainCleanup
{
public:
    CMainCleanup() {}
    ~CMainCleanup() {
        // block headers
        std::map<uint256, CBlockIndex*>::iterator it1 = mapBlockIndex.begin();
        for (; it1 != mapBlockIndex.end(); it1++)
            delete (*it1).second;
        mapBlockIndex.clear();

        // orphan blocks
        std::map<uint256, CBlock*>::iterator it2 = mapOrphanBlocks.begin();
        for (; it2 != mapOrphanBlocks.end(); it2++)
            delete (*it2).second;
        mapOrphanBlocks.clear();

        // orphan transactions
        mapOrphanTransactions.clear();
    }
} instance_of_cmaincleanup;