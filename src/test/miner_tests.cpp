#include <boost/test/unit_test.hpp>

#include "init.h"
#include "main.h"
#include "uint256.h"
#include "util.h"
#include "wallet.h"

extern void SHA256Transform(void* pstate, void* pinput, const void* pinit);

BOOST_AUTO_TEST_SUITE(miner_tests)

static
struct {
    unsigned char extranonce;
    unsigned int nonce;
} blockinfo[] = {
    {0,  485620}, {0,  1313570}, {0,  1427977}, {0,  881757},
    {0,  166059}, {0,  1467245}, {0,  650707}, {0,  3012782},
    {0,  22256}, {0,  315868}, {0,  191591}, {0,  90455},
    {0,  259742}, {0,  285170}, {0,  306353}, {0,  1779746},
    {0,  1456538}, {0,  365826}, {0,  551720}, {0,  2154},
    {0,  3480677}, {0,  1106247}, {0,  4498476}, {0,  31876},
    {0,  1464164}, {0,  1341575}, {0,  81652}, {0,  1306582},
    {0,  4725550}, {0,  1314926}, {0,  2188928}, {0,  2428258},
    {0,  222786}, {0,  271449}, {0,  767753}, {0,  235492},
    {0,  1068131}, {0,  21501}, {0,  1513107}, {0,  1534775},
    {0,  960921}, {0,  5340054}, {0,  597843}, {0,  1867048},
    {0,  958421}, {0,  735681}, {0,  720239}, {0,  1489636},
    {0,  476580}, {0,  687332},
};

// NOTE: These tests rely on CreateNewBlock doing its own self-validation!
BOOST_AUTO_TEST_CASE(CreateNewBlock_validity)
{
    CReserveKey reservekey(pwalletMain);
    CBlockTemplate *pblocktemplate;
    CTransaction tx;
    CScript script;
    uint256 hash;

    // Simple block creation, nothing special yet:
    BOOST_CHECK(pblocktemplate = CreateNewBlockWithKey(reservekey));

    // We can't make transactions until we have inputs
    // Therefore, load 50 blocks :)
    std::vector<CTransaction*>txFirst;
    for (unsigned int i = 0; i < sizeof(blockinfo)/sizeof(*blockinfo); ++i)
    {
        CBlock *pblock = &pblocktemplate->block; // pointer for convenience
        pblock->nVersion = 2;
        pblock->nTime = pindexBest->GetMedianTimePast()+1;
        pblock->vtx[0].vin[0].scriptSig = CScript();
        pblock->vtx[0].vin[0].scriptSig.push_back(blockinfo[i].extranonce);
        pblock->vtx[0].vin[0].scriptSig.push_back(pindexBest->nHeight);
        pblock->vtx[0].vout[0].scriptPubKey = CScript();
        if (txFirst.size() < 2)
            txFirst.push_back(new CTransaction(pblock->vtx[0]));
        pblock->hashMerkleRoot = pblock->BuildMerkleTree();
        pblock->nNonce = blockinfo[i].nonce;
        CValidationState state;
        BOOST_CHECK(ProcessBlock(state, NULL, pblock));
        BOOST_CHECK(state.IsValid());
        pblock->hashPrevBlock = pblock->GetHash();
    }
    delete pblocktemplate;

    // Just to make sure we can still make simple blocks
    BOOST_CHECK(pblocktemplate = CreateNewBlockWithKey(reservekey));
    delete pblocktemplate;

    // block sigops > limit: 1000 CHECKMULTISIG + 1
    tx.vin.resize(1);
    // NOTE: OP_NOP is used to force 20 SigOps for the CHECKMULTISIG
    tx.vin[0].scriptSig = CScript() << OP_0 << OP_0 << OP_0 << OP_NOP << OP_CHECKMULTISIG << OP_1;
    tx.vin[0].prevout.hash = txFirst[0]->GetHash();
    tx.vin[0].prevout.n = 0;
    tx.vout.resize(1);
    tx.vout[0].nValue = 5000000000LL;
    for (unsigned int i = 0; i < 1001; ++i)
    {
        tx.vout[0].nValue -= 1000000;
        hash = tx.GetHash();
        mempool.addUnchecked(hash, tx);
        tx.vin[0].prevout.hash = hash;
    }
    BOOST_CHECK(pblocktemplate = CreateNewBlockWithKey(reservekey));
    delete pblocktemplate;
    mempool.clear();

    // block size > limit
    tx.vin[0].scriptSig = CScript();
    // 18 * (520char + DROP) + OP_1 = 9433 bytes
    std::vector<unsigned char> vchData(520);
    for (unsigned int i = 0; i < 18; ++i)
        tx.vin[0].scriptSig << vchData << OP_DROP;
    tx.vin[0].scriptSig << OP_1;
    tx.vin[0].prevout.hash = txFirst[0]->GetHash();
    tx.vout[0].nValue = 5000000000LL;
    for (unsigned int i = 0; i < 128; ++i)
    {
        tx.vout[0].nValue -= 10000000;
        hash = tx.GetHash();
        mempool.addUnchecked(hash, tx);
        tx.vin[0].prevout.hash = hash;
    }
    BOOST_CHECK(pblocktemplate = CreateNewBlockWithKey(reservekey));
    delete pblocktemplate;
    mempool.clear();

    // orphan in mempool
    hash = tx.GetHash();
    mempool.addUnchecked(hash, tx);
    BOOST_CHECK(pblocktemplate = CreateNewBlockWithKey(reservekey));
    delete pblocktemplate;
    mempool.clear();

    // child with higher priority than parent
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vin[0].prevout.hash = txFirst[1]->GetHash();
    tx.vout[0].nValue = 4900000000LL;
    hash = tx.GetHash();
    mempool.addUnchecked(hash, tx);
    tx.vin[0].prevout.hash = hash;
    tx.vin.resize(2);
    tx.vin[1].scriptSig = CScript() << OP_1;
    tx.vin[1].prevout.hash = txFirst[0]->GetHash();
    tx.vin[1].prevout.n = 0;
    tx.vout[0].nValue = 5900000000LL;
    hash = tx.GetHash();
    mempool.addUnchecked(hash, tx);
    BOOST_CHECK(pblocktemplate = CreateNewBlockWithKey(reservekey));
    delete pblocktemplate;
    mempool.clear();

    // coinbase in mempool
    tx.vin.resize(1);
    tx.vin[0].prevout.SetNull();
    tx.vin[0].scriptSig = CScript() << OP_0 << OP_1;
    tx.vout[0].nValue = 0;
    hash = tx.GetHash();
    mempool.addUnchecked(hash, tx);
    BOOST_CHECK(pblocktemplate = CreateNewBlockWithKey(reservekey));
    delete pblocktemplate;
    mempool.clear();

    // invalid (pre-p2sh) txn in mempool
    tx.vin[0].prevout.hash = txFirst[0]->GetHash();
    tx.vin[0].prevout.n = 0;
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vout[0].nValue = 4900000000LL;
    script = CScript() << OP_0;
    tx.vout[0].scriptPubKey.SetDestination(script.GetID());
    hash = tx.GetHash();
    mempool.addUnchecked(hash, tx);
    tx.vin[0].prevout.hash = hash;
    tx.vin[0].scriptSig = CScript() << (std::vector<unsigned char>)script;
    tx.vout[0].nValue -= 1000000;
    hash = tx.GetHash();
    mempool.addUnchecked(hash,tx);
    BOOST_CHECK(pblocktemplate = CreateNewBlockWithKey(reservekey));
    delete pblocktemplate;
    mempool.clear();

    // double spend txn pair in mempool
    tx.vin[0].prevout.hash = txFirst[0]->GetHash();
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vout[0].nValue = 4900000000LL;
    tx.vout[0].scriptPubKey = CScript() << OP_1;
    hash = tx.GetHash();
    mempool.addUnchecked(hash, tx);
    tx.vout[0].scriptPubKey = CScript() << OP_2;
    hash = tx.GetHash();
    mempool.addUnchecked(hash, tx);
    BOOST_CHECK(pblocktemplate = CreateNewBlockWithKey(reservekey));
    delete pblocktemplate;
    mempool.clear();

    // subsidy changing
    int nHeight = pindexBest->nHeight;
    pindexBest->nHeight = 209999;
    BOOST_CHECK(pblocktemplate = CreateNewBlockWithKey(reservekey));
    delete pblocktemplate;
    pindexBest->nHeight = 210000;
    BOOST_CHECK(pblocktemplate = CreateNewBlockWithKey(reservekey));
    delete pblocktemplate;
    pindexBest->nHeight = nHeight;

    BOOST_FOREACH(CTransaction *tx, txFirst)
        delete tx;
}

BOOST_AUTO_TEST_CASE(sha256transform_equality)
{
    unsigned int pSHA256InitState[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};


    // unsigned char pstate[32];
    unsigned char pinput[64];

    int i;

    for (i = 0; i < 32; i++) {
        pinput[i] = i;
        pinput[i+32] = 0;
    }

    uint256 hash;

    SHA256Transform(&hash, pinput, pSHA256InitState);

    BOOST_TEST_MESSAGE(hash.GetHex());

    uint256 hash_reference("0x2df5e1c65ef9f8cde240d23cae2ec036d31a15ec64bc68f64be242b1da6631f3");

    BOOST_CHECK(hash == hash_reference);
}

BOOST_AUTO_TEST_SUITE_END()
