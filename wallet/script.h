// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef H_BITCOIN_SCRIPT
#define H_BITCOIN_SCRIPT

#include <string>
#include <vector>

#include <stdint.h>

#include <boost/foreach.hpp>
#include <boost/variant.hpp>

#include "bignum.h"
#include "keystore.h"
#include "result.h"
#include "script_error.h"
#include "wallet_ismine.h"

typedef std::vector<unsigned char> valtype;

class CTransaction;
class ITxDB;

static const unsigned int MAX_SCRIPT_ELEMENT_SIZE = 520; // bytes

// Maximum script length in bytes
static const int MAX_SCRIPT_SIZE = 10000;

/** Maximum number of signature check operations in an IsStandard() P2SH script */
static const unsigned int MAX_P2SH_SIGOPS = 15;

/// Setting nSequence to this value for every input in a transaction
/// disables nLockTime.
static const uint32_t SEQUENCE_FINAL = 0xffffffff;

/// If this flag set, CTxIn::nSequence is NOT interpreted as a
/// relative lock-time.

// Constant not used currently due to lack of OP_CHECKSEQUENCEVERIFY check (NOP3)
static const uint32_t SEQUENCE_LOCKTIME_DISABLE_FLAG = 0x80000000;

/// If CTxIn::nSequence encodes a relative lock-time and this flag
/// is set, the relative lock-time has units of 512 seconds,
/// otherwise it specifies blocks with a granularity of 1.

// Constant not used currently due to lack of OP_CHECKSEQUENCEVERIFY check (NOP3)
static const uint32_t SEQUENCE_LOCKTIME_TYPE_FLAG = 0x00400000;

/// If CTxIn::nSequence encodes a relative lock-time, this mask is
/// applied to extract that lock-time from the sequence field.

// Constant not used currently due to lack of OP_CHECKSEQUENCEVERIFY check (NOP3)
static const uint32_t SEQUENCE_LOCKTIME_MASK = 0x0000ffff;

/// A timestamp in the blockchain where LOCKTIME Verify Activates

// Saturday, June 15, 2019 16:00:00 UTC
static const unsigned int CHECKLOCKTIME_VERIFY_SWITCH_TIME = 1560614400;

/** Signature hash types/flags */
enum
{
    SIGHASH_ALL          = 1,
    SIGHASH_NONE         = 2,
    SIGHASH_SINGLE       = 3,
    SIGHASH_ANYONECANPAY = 0x80,
};

enum txnouttype
{
    TX_NONSTANDARD,
    // 'standard' transaction types:
    TX_PUBKEY,
    TX_PUBKEYHASH,
    TX_SCRIPTHASH,
    TX_MULTISIG,
    TX_NULL_DATA,
    TX_COLDSTAKE,
};

class CNoDestination
{
public:
    friend bool operator==(const CNoDestination& /*a*/, const CNoDestination& /*b*/) { return true; }
    friend bool operator<(const CNoDestination& /*a*/, const CNoDestination& /*b*/) { return true; }
};

/** A txout script template with a specific destination. It is either:
 *  * CNoDestination: no destination set
 *  * CKeyID: TX_PUBKEYHASH destination
 *  * CScriptID: TX_SCRIPTHASH destination
 *  A CTxDestination is the internal data type encoded in a CBitcoinAddress
 */
typedef boost::variant<CNoDestination, CKeyID, CScriptID> CTxDestination;

const char* GetTxnOutputType(txnouttype t);

/** Script opcodes */
enum opcodetype
{
    // push value
    OP_0         = 0x00,
    OP_FALSE     = OP_0,
    OP_PUSHDATA1 = 0x4c,
    OP_PUSHDATA2 = 0x4d,
    OP_PUSHDATA4 = 0x4e,
    OP_1NEGATE   = 0x4f,
    OP_RESERVED  = 0x50,
    OP_1         = 0x51,
    OP_TRUE      = OP_1,
    OP_2         = 0x52,
    OP_3         = 0x53,
    OP_4         = 0x54,
    OP_5         = 0x55,
    OP_6         = 0x56,
    OP_7         = 0x57,
    OP_8         = 0x58,
    OP_9         = 0x59,
    OP_10        = 0x5a,
    OP_11        = 0x5b,
    OP_12        = 0x5c,
    OP_13        = 0x5d,
    OP_14        = 0x5e,
    OP_15        = 0x5f,
    OP_16        = 0x60,

    // control
    OP_NOP                 = 0x61,
    OP_VER                 = 0x62,
    OP_IF                  = 0x63,
    OP_NOTIF               = 0x64,
    OP_VERIF               = 0x65,
    OP_VERNOTIF            = 0x66,
    OP_ELSE                = 0x67,
    OP_ENDIF               = 0x68,
    OP_VERIFY              = 0x69,
    OP_RETURN              = 0x6a,
    OP_CHECKLOCKTIMEVERIFY = 0xb1,
    OP_CHECKSEQUENCEVERIFY =
        0xb2, // Currently still acts as NOP3 as OP_CHECKSEQUENCEVERIFY is not implemented

    // stack ops
    OP_TOALTSTACK   = 0x6b,
    OP_FROMALTSTACK = 0x6c,
    OP_2DROP        = 0x6d,
    OP_2DUP         = 0x6e,
    OP_3DUP         = 0x6f,
    OP_2OVER        = 0x70,
    OP_2ROT         = 0x71,
    OP_2SWAP        = 0x72,
    OP_IFDUP        = 0x73,
    OP_DEPTH        = 0x74,
    OP_DROP         = 0x75,
    OP_DUP          = 0x76,
    OP_NIP          = 0x77,
    OP_OVER         = 0x78,
    OP_PICK         = 0x79,
    OP_ROLL         = 0x7a,
    OP_ROT          = 0x7b,
    OP_SWAP         = 0x7c,
    OP_TUCK         = 0x7d,

    // splice ops
    OP_CAT    = 0x7e,
    OP_SUBSTR = 0x7f,
    OP_LEFT   = 0x80,
    OP_RIGHT  = 0x81,
    OP_SIZE   = 0x82,

    // bit logic
    OP_INVERT      = 0x83,
    OP_AND         = 0x84,
    OP_OR          = 0x85,
    OP_XOR         = 0x86,
    OP_EQUAL       = 0x87,
    OP_EQUALVERIFY = 0x88,
    OP_RESERVED1   = 0x89,
    OP_RESERVED2   = 0x8a,

    // numeric
    OP_1ADD      = 0x8b,
    OP_1SUB      = 0x8c,
    OP_2MUL      = 0x8d,
    OP_2DIV      = 0x8e,
    OP_NEGATE    = 0x8f,
    OP_ABS       = 0x90,
    OP_NOT       = 0x91,
    OP_0NOTEQUAL = 0x92,

    OP_ADD    = 0x93,
    OP_SUB    = 0x94,
    OP_MUL    = 0x95,
    OP_DIV    = 0x96,
    OP_MOD    = 0x97,
    OP_LSHIFT = 0x98,
    OP_RSHIFT = 0x99,

    OP_BOOLAND            = 0x9a,
    OP_BOOLOR             = 0x9b,
    OP_NUMEQUAL           = 0x9c,
    OP_NUMEQUALVERIFY     = 0x9d,
    OP_NUMNOTEQUAL        = 0x9e,
    OP_LESSTHAN           = 0x9f,
    OP_GREATERTHAN        = 0xa0,
    OP_LESSTHANOREQUAL    = 0xa1,
    OP_GREATERTHANOREQUAL = 0xa2,
    OP_MIN                = 0xa3,
    OP_MAX                = 0xa4,

    OP_WITHIN = 0xa5,

    // crypto
    OP_RIPEMD160           = 0xa6,
    OP_SHA1                = 0xa7,
    OP_SHA256              = 0xa8,
    OP_HASH160             = 0xa9,
    OP_HASH256             = 0xaa,
    OP_CODESEPARATOR       = 0xab,
    OP_CHECKSIG            = 0xac,
    OP_CHECKSIGVERIFY      = 0xad,
    OP_CHECKMULTISIG       = 0xae,
    OP_CHECKMULTISIGVERIFY = 0xaf,

    // expansion
    OP_NOP1  = 0xb0,
    OP_NOP4  = 0xb3,
    OP_NOP5  = 0xb4,
    OP_NOP6  = 0xb5,
    OP_NOP7  = 0xb6,
    OP_NOP8  = 0xb7,
    OP_NOP9  = 0xb8,
    OP_NOP10 = 0xb9,

    // cold staking
    OP_CHECKCOLDSTAKEVERIFY = 0xd1,

    // template matching params
    OP_SMALLDATA    = 0xf9,
    OP_SMALLINTEGER = 0xfa,
    OP_PUBKEYS      = 0xfb,
    OP_PUBKEYHASH   = 0xfd,
    OP_PUBKEY       = 0xfe,

    OP_INVALIDOPCODE = 0xff,
};

const char* GetOpName(opcodetype opcode);

inline std::string ValueString(const std::vector<unsigned char>& vch)
{
    if (vch.size() <= 4)
        return fmt::format("{}", CBigNum(vch).getint());
    else
        return HexStr(vch);
}

inline std::string StackString(const std::vector<std::vector<unsigned char>>& vStack)
{
    std::string str;
    BOOST_FOREACH (const std::vector<unsigned char>& vch, vStack) {
        if (!str.empty())
            str += " ";
        str += ValueString(vch);
    }
    return str;
}

////////////////////////////////

/** Serialized script, used inside transaction inputs and outputs */
class CScript : public std::vector<unsigned char>
{
protected:
    CScript& push_int64(int64_t n)
    {
        if (n == -1 || (n >= 1 && n <= 16)) {
            push_back(n + (OP_1 - 1));
        } else {
            CBigNum bn(n);
            *this << bn.getvch();
        }
        return *this;
    }

    CScript& push_uint64(uint64_t n)
    {
        if (n >= 1 && n <= 16) {
            push_back(n + (OP_1 - 1));
        } else {
            CBigNum bn(n);
            *this << bn.getvch();
        }
        return *this;
    }

public:
    CScript() {}
    CScript(const_iterator pbegin, const_iterator pend) : std::vector<unsigned char>(pbegin, pend) {}
#ifndef _MSC_VER
    CScript(const unsigned char* pbegin, const unsigned char* pend)
        : std::vector<unsigned char>(pbegin, pend)
    {
    }
#endif

    CScript& operator+=(const CScript& b)
    {
        insert(end(), b.begin(), b.end());
        return *this;
    }

    friend CScript operator+(const CScript& a, const CScript& b)
    {
        CScript ret = a;
        ret += b;
        return ret;
    }

    // explicit CScript(char b) is not portable.  Use 'signed char' or 'unsigned char'.
    explicit CScript(signed char b) { operator<<(b); }
    explicit CScript(short b) { operator<<(b); }
    explicit CScript(int b) { operator<<(b); }
    explicit CScript(long b) { operator<<(b); }
    explicit CScript(long long b) { operator<<(b); }
    explicit CScript(unsigned char b) { operator<<(b); }
    explicit CScript(unsigned int b) { operator<<(b); }
    explicit CScript(unsigned short b) { operator<<(b); }
    explicit CScript(unsigned long b) { operator<<(b); }
    explicit CScript(unsigned long long b) { operator<<(b); }

    explicit CScript(opcodetype b) { operator<<(b); }
    explicit CScript(const uint256& b) { operator<<(b); }
    explicit CScript(const CBigNum& b) { operator<<(b); }
    explicit CScript(const std::vector<unsigned char>& b) { operator<<(b); }

    // CScript& operator<<(char b) is not portable.  Use 'signed char' or 'unsigned char'.
    CScript& operator<<(signed char b) { return push_int64(b); }
    CScript& operator<<(short b) { return push_int64(b); }
    CScript& operator<<(int b) { return push_int64(b); }
    CScript& operator<<(long b) { return push_int64(b); }
    CScript& operator<<(long long b) { return push_int64(b); }
    CScript& operator<<(unsigned char b) { return push_uint64(b); }
    CScript& operator<<(unsigned int b) { return push_uint64(b); }
    CScript& operator<<(unsigned short b) { return push_uint64(b); }
    CScript& operator<<(unsigned long b) { return push_uint64(b); }
    CScript& operator<<(unsigned long long b) { return push_uint64(b); }

    CScript& operator<<(opcodetype opcode)
    {
        if (opcode < 0 || opcode > 0xff)
            throw std::runtime_error("CScript::operator<<() : invalid opcode");
        insert(end(), (unsigned char)opcode);
        return *this;
    }

    CScript& operator<<(const uint160& b)
    {
        insert(end(), sizeof(b));
        insert(end(), (unsigned char*)&b, (unsigned char*)&b + sizeof(b));
        return *this;
    }

    CScript& operator<<(const uint256& b)
    {
        insert(end(), sizeof(b));
        insert(end(), (unsigned char*)&b, (unsigned char*)&b + sizeof(b));
        return *this;
    }

    CScript& operator<<(const CPubKey& key)
    {
        std::vector<unsigned char> vchKey = key.Raw();
        return (*this) << vchKey;
    }

    CScript& operator<<(const CBigNum& b)
    {
        *this << b.getvch();
        return *this;
    }

    CScript& operator<<(const std::vector<unsigned char>& b)
    {
        if (b.size() < OP_PUSHDATA1) {
            insert(end(), (unsigned char)b.size());
        } else if (b.size() <= 0xff) {
            insert(end(), OP_PUSHDATA1);
            insert(end(), (unsigned char)b.size());
        } else if (b.size() <= 0xffff) {
            insert(end(), OP_PUSHDATA2);
            unsigned short nSize = b.size();
            insert(end(), (unsigned char*)&nSize, (unsigned char*)&nSize + sizeof(nSize));
        } else {
            insert(end(), OP_PUSHDATA4);
            unsigned int nSize = b.size();
            insert(end(), (unsigned char*)&nSize, (unsigned char*)&nSize + sizeof(nSize));
        }
        insert(end(), b.begin(), b.end());
        return *this;
    }

    CScript& operator<<(const CScript& /*b*/)
    {
        // I'm not sure if this should push the script or concatenate scripts.
        // If there's ever a use for pushing a script onto a script, delete this member fn
        assert(!"Warning: Pushing a CScript onto a CScript with << is probably not intended, use + to "
                "concatenate!");
        return *this;
    }

    bool GetOp(iterator& pc, opcodetype& opcodeRet, std::vector<unsigned char>& vchRet)
    {
        // Wrapper so it can be called with either iterator or const_iterator
        const_iterator pc2  = pc;
        bool           fRet = GetOp2(pc2, opcodeRet, &vchRet);
        pc                  = begin() + (pc2 - begin());
        return fRet;
    }

    bool GetOp(iterator& pc, opcodetype& opcodeRet)
    {
        const_iterator pc2  = pc;
        bool           fRet = GetOp2(pc2, opcodeRet, NULL);
        pc                  = begin() + (pc2 - begin());
        return fRet;
    }

    bool GetOp(const_iterator& pc, opcodetype& opcodeRet, std::vector<unsigned char>& vchRet) const
    {
        return GetOp2(pc, opcodeRet, &vchRet);
    }

    bool GetOp(const_iterator& pc, opcodetype& opcodeRet) const { return GetOp2(pc, opcodeRet, NULL); }

    bool GetOp2(const_iterator& pc, opcodetype& opcodeRet, std::vector<unsigned char>* pvchRet) const
    {
        opcodeRet = OP_INVALIDOPCODE;
        if (pvchRet)
            pvchRet->clear();
        if (pc >= end())
            return false;

        // Read instruction
        if (end() - pc < 1)
            return false;
        unsigned int opcode = *pc++;

        // Immediate operand
        if (opcode <= OP_PUSHDATA4) {
            unsigned int nSize;
            if (opcode < OP_PUSHDATA1) {
                nSize = opcode;
            } else if (opcode == OP_PUSHDATA1) {
                if (end() - pc < 1)
                    return false;
                nSize = *pc++;
            } else if (opcode == OP_PUSHDATA2) {
                if (end() - pc < 2)
                    return false;
                nSize = 0;
                memcpy(&nSize, &pc[0], 2);
                pc += 2;
            } else if (opcode == OP_PUSHDATA4) {
                if (end() - pc < 4)
                    return false;
                memcpy(&nSize, &pc[0], 4);
                pc += 4;
            }
            if (end() - pc < 0 || (unsigned int)(end() - pc) < nSize)
                return false;
            if (pvchRet)
                pvchRet->assign(pc, pc + nSize);
            pc += nSize;
        }

        opcodeRet = (opcodetype)opcode;
        return true;
    }

    // Encode/decode small integers:
    static int DecodeOP_N(opcodetype opcode)
    {
        if (opcode == OP_0)
            return 0;
        assert(opcode >= OP_1 && opcode <= OP_16);
        return (int)opcode - (int)(OP_1 - 1);
    }
    static opcodetype EncodeOP_N(int n)
    {
        assert(n >= 0 && n <= 16);
        if (n == 0)
            return OP_0;
        return (opcodetype)(OP_1 + n - 1);
    }

    int FindAndDelete(const CScript& b)
    {
        int nFound = 0;
        if (b.empty())
            return nFound;
        iterator   pc = begin();
        opcodetype opcode;
        do {
            while (end() - pc >= (long)b.size() && memcmp(&pc[0], &b[0], b.size()) == 0) {
                erase(pc, pc + b.size());
                ++nFound;
            }
        } while (GetOp(pc, opcode));
        return nFound;
    }
    int Find(opcodetype op) const
    {
        int        nFound = 0;
        opcodetype opcode;
        for (const_iterator pc = begin(); pc != end() && GetOp(pc, opcode);)
            if (opcode == op)
                ++nFound;
        return nFound;
    }

    // Pre-version-0.6, Bitcoin always counted CHECKMULTISIGs
    // as 20 sigops. With pay-to-script-hash, that changed:
    // CHECKMULTISIGs serialized in scriptSigs are
    // counted more accurately, assuming they are of the form
    //  ... OP_N CHECKMULTISIG ...
    unsigned int GetSigOpCount(bool fAccurate) const;

    // Accurately count sigOps, including sigOps in
    // pay-to-script-hash transactions:
    unsigned int GetSigOpCount(const CScript& scriptSig) const;

    bool IsPayToScriptHash() const;

    bool IsPayToColdStaking() const;

    /**
     * Checks if the scriptSig is for P2CS; if yes, returns the public key; if no returns boost::none
     */
    boost::optional<std::vector<uint8_t>> GetPubKeyOfP2CSScriptSig() const;

    // Called by IsStandardTx and P2SH VerifyScript (which makes it consensus-critical).
    bool IsPushOnly() const
    {
        const_iterator pc = begin();
        while (pc < end()) {
            opcodetype opcode;
            if (!GetOp(pc, opcode))
                return false;
            if (opcode > OP_16)
                return false;
        }
        return true;
    }

    // Called by IsStandardTx.
    bool HasCanonicalPushes() const;

    void SetDestination(const CTxDestination& address);
    void SetMultisig(int nRequired, const std::vector<CKey>& keys);

    std::string ToString(bool fShort = false) const
    {
        std::string                str;
        opcodetype                 opcode;
        std::vector<unsigned char> vch;
        const_iterator             pc = begin();
        while (pc < end()) {
            if (!str.empty())
                str += " ";
            if (!GetOp(pc, opcode, vch)) {
                str += "[error]";
                return str;
            }
            if (0 <= opcode && opcode <= OP_PUSHDATA4)
                str += fShort ? ValueString(vch).substr(0, 10) : ValueString(vch);
            else
                str += GetOpName(opcode);
        }
        return str;
    }

    CScriptID GetID() const { return CScriptID(Hash160(*this)); }
};

/** Compact serializer for scripts.
 *
 *  It detects common cases and encodes them much more efficiently.
 *  3 special cases are defined:
 *  * Pay to pubkey hash (encoded as 21 bytes)
 *  * Pay to script hash (encoded as 21 bytes)
 *  * Pay to pubkey starting with 0x02, 0x03 or 0x04 (encoded as 33 bytes)
 *
 *  Other scripts up to 121 bytes require 1 byte + script length. Above
 *  that, scripts up to 16505 bytes require 2 bytes + script length.
 */
class CScriptCompressor
{
private:
    // make this static for now (there are only 6 special scripts defined)
    // this can potentially be extended together with a new nVersion for
    // transactions, in which case this value becomes dependent on nVersion
    // and nHeight of the enclosing transaction.
    static const unsigned int nSpecialScripts = 6;

    CScript& script;

protected:
    // These check for scripts for which a special case with a shorter encoding is defined.
    // They are implemented separately from the CScript test, as these test for exact byte
    // sequence correspondences, and are more strict. For example, IsToPubKey also verifies
    // whether the public key is valid (as invalid ones cannot be represented in compressed
    // form).
    bool IsToKeyID(CKeyID& hash) const;
    bool IsToScriptID(CScriptID& hash) const;
    bool IsToPubKey(std::vector<unsigned char>& pubkey) const;

    bool         Compress(std::vector<unsigned char>& out) const;
    unsigned int GetSpecialSize(unsigned int nSize) const;
    bool         Decompress(unsigned int nSize, const std::vector<unsigned char>& out);

public:
    CScriptCompressor(CScript& scriptIn) : script(scriptIn) {}

    unsigned int GetSerializeSize(int nType, int nVersion) const
    {
        std::vector<unsigned char> compr;
        if (Compress(compr))
            return compr.size();
        unsigned int nSize = script.size() + nSpecialScripts;
        return script.size() + VARINT(nSize).GetSerializeSize(nType, nVersion);
    }

    template <typename Stream>
    void Serialize(Stream& s, int /*nType*/, int /*nVersion*/) const
    {
        std::vector<unsigned char> compr;
        if (Compress(compr)) {
            s << CFlatData(&compr[0], &compr[compr.size()]);
            return;
        }
        unsigned int nSize = script.size() + nSpecialScripts;
        s << VARINT(nSize);
        s << CFlatData(&script[0], &script[script.size()]);
    }

    template <typename Stream>
    void Unserialize(Stream& s, int /*nType*/, int /*nVersion*/)
    {
        unsigned int nSize;
        s >> VARINT(nSize);
        if (nSize < nSpecialScripts) {
            std::vector<unsigned char> vch(GetSpecialSize(nSize), 0x00);
            s >> REF(CFlatData(&vch[0], &vch[vch.size()]));
            Decompress(nSize, vch);
            return;
        }
        nSize -= nSpecialScripts;
        script.resize(nSize);
        s >> REF(CFlatData(&script[0], &script[script.size()]));
    }
};

enum class SignatureState : uint32_t
{
    // signature successful, and it was verified that
    Verified,
    // signature successful, but it wasn't verified
    Unverified,
    // signature failed
    Failed
};

bool IsCanonicalPubKey(const std::vector<unsigned char>& vchPubKey);
bool IsCanonicalSignature(const std::vector<unsigned char>& vchSig);

CScript GetScriptForDestination(const CTxDestination& dest);
CScript GetScriptForStakeDelegation(const CKeyID& stakingKey, const CKeyID& spendingKey);
Result<void, ScriptError> EvalScript(std::vector<std::vector<unsigned char>>& stack,
                                     const CScript& script, const CTransaction& txTo, unsigned int nIn,
                                     bool fStrictEncodings, int nHashType,
                                     ScriptError* serror = nullptr);
bool                      Solver(const ITxDB& txdb, const CScript& scriptPubKey, txnouttype& typeRet,
                                 std::vector<std::vector<unsigned char>>& vSolutionsRet);
int  ScriptSigArgsExpected(txnouttype t, const std::vector<std::vector<unsigned char>>& vSolutions);
bool IsStandard(const ITxDB& txdb, const CScript& scriptPubKey, txnouttype& whichType);
isminetype IsMine(const CKeyStore& keystore, const CScript& scriptPubKey);
isminetype IsMine(const CKeyStore& keystore, const CTxDestination& dest);

void ExtractAffectedKeys(const ITxDB& txdb, const CKeyStore& keystore, const CScript& scriptPubKey,
                         std::vector<CKeyID>& vKeys);
bool ExtractDestination(const ITxDB& txdb, const CScript& scriptPubKey, CTxDestination& addressRet,
                        bool fColdStake = false);
bool ExtractKeyID(const ITxDB& txdb, const CScript& scriptPubKey, CKeyID& addressRet);
bool ExtractDestinations(const ITxDB& txdb, const CScript& scriptPubKey, txnouttype& typeRet,
                         std::vector<CTxDestination>& addressRet, int& nRequiredRet);
SignatureState SignSignature(const CKeyStore& keystore, const CScript& fromPubKey, CTransaction& txTo,
                             unsigned int nIn, int nHashType = SIGHASH_ALL, bool fColdStake = false);
SignatureState SignSignature(const CKeyStore& keystore, const CTransaction& txFrom, CTransaction& txTo,
                             unsigned int nIn, int nHashType = SIGHASH_ALL, bool fColdStake = false);
Result<void, ScriptError> VerifyScript(const CScript& scriptSig, const CScript& scriptPubKey,
                                       const CTransaction& txTo, unsigned int nIn,
                                       bool fValidatePayToScriptHash, bool fStrictEncodings,
                                       int nHashType);
Result<void, ScriptError> VerifySignature(const CTransaction& txFrom, const CTransaction& txTo,
                                          unsigned int nIn, bool fValidatePayToScriptHash,
                                          bool fStrictEncodings, int nHashType);

// Given two sets of signatures for scriptPubKey, possibly with OP_0 placeholders,
// combine them intelligently and return the result.
CScript CombineSignatures(CScript scriptPubKey, const CTransaction& txTo, unsigned int nIn,
                          const CScript& scriptSig1, const CScript& scriptSig2);

class CReserveScript
{
public:
    CScript      reserveScript;
    virtual void KeepScript() {}
    CReserveScript() {}
    virtual ~CReserveScript() {}
};

#endif
