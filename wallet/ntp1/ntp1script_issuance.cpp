#include "ntp1script_issuance.h"

#include "base58.h"
#include "hash.h"
#include "util.h"
#include <boost/algorithm/hex.hpp>

std::string NTP1Script_Issuance::__getAggregAndLockStatusTokenIDHexValue() const
{
    std::string aggregatableHex;
    if (isLocked()) {
        if (getAggregationPolicy() == IssuanceFlags::AggregationPolicy::AggregationPolicy_Aggregatable) {
            aggregatableHex = "20ce";
        } else if (getAggregationPolicy() ==
                   IssuanceFlags::AggregationPolicy::AggregationPolicy_NonAggregatable) {
            aggregatableHex = "20e4";
        } else {
            throw std::runtime_error("Unknown aggregation policity for token: " + getTokenSymbol());
        }
    } else {
        if (getAggregationPolicy() == IssuanceFlags::AggregationPolicy::AggregationPolicy_Aggregatable) {
            aggregatableHex = "2e37";
        } else if (getAggregationPolicy() ==
                   IssuanceFlags::AggregationPolicy::AggregationPolicy_NonAggregatable) {
            aggregatableHex = "2e4e";
        } else {
            throw std::runtime_error("Unknown aggregation policity for token: " + getTokenSymbol());
        }
    }
    return aggregatableHex;
}

NTP1Script_Issuance::NTP1Script_Issuance() {}

std::string NTP1Script_Issuance::getHexMetadata() const { return boost::algorithm::hex(metadata); }

std::string NTP1Script_Issuance::getRawMetadata() const { return metadata; }

int NTP1Script_Issuance::getDivisibility() const { return issuanceFlags.divisibility; }

bool NTP1Script_Issuance::isLocked() const { return issuanceFlags.locked; }

NTP1Script::IssuanceFlags::AggregationPolicy NTP1Script_Issuance::getAggregationPolicy() const
{
    return issuanceFlags.aggregationPolicty;
}

std::string NTP1Script_Issuance::getAggregationPolicyStr() const
{
    if (issuanceFlags.aggregationPolicty == NTP1Script::IssuanceFlags::AggregationPolicy_Aggregatable) {
        return "aggregatable";
    } else if (issuanceFlags.aggregationPolicty ==
               NTP1Script::IssuanceFlags::AggregationPolicy_Aggregatable) {
        return "nonaggregatable";
    } else {
        return "aggregatable";
    }
}

std::string NTP1Script_Issuance::getTokenSymbol() const { return tokenSymbol; }

uint64_t NTP1Script_Issuance::getAmount() const { return amount; }

unsigned NTP1Script_Issuance::getTransferInstructionsCount() const
{
    return transferInstructions.size();
}

NTP1Script::TransferInstruction NTP1Script_Issuance::getTransferInstruction(unsigned index) const
{
    return transferInstructions[index];
}

std::vector<NTP1Script::TransferInstruction> NTP1Script_Issuance::getTransferInstructions() const
{
    return transferInstructions;
}

std::shared_ptr<NTP1Script_Issuance>
NTP1Script_Issuance::ParseIssuancePostHeaderData(std::string ScriptBin, std::string OpCodeBin)
{
    std::shared_ptr<NTP1Script_Issuance> result = std::make_shared<NTP1Script_Issuance>();

    // get token symbol (size always = 5 bytes)
    result->tokenSymbol = ParseTokenSymbolFromLongEnoughString(ScriptBin);
    ScriptBin.erase(ScriptBin.begin(), ScriptBin.begin() + 5);

    // get metadata then drop it
    result->metadata = ParseMetadataFromLongEnoughString(ScriptBin, OpCodeBin);
    ScriptBin.erase(ScriptBin.begin(), ScriptBin.begin() + result->metadata.size());

    // parse amount
    int amountRawSize = 0;
    result->amount    = ParseAmountFromLongEnoughString(ScriptBin, amountRawSize);
    ScriptBin.erase(ScriptBin.begin(), ScriptBin.begin() + amountRawSize);

    // parse transfer instructions
    int totalTransferInstructionsSize = 0;
    result->transferInstructions =
        ParseTransferInstructionsFromLongEnoughString(ScriptBin, totalTransferInstructionsSize);
    ScriptBin.erase(ScriptBin.begin(), ScriptBin.begin() + totalTransferInstructionsSize);

    // check that no skip transfer instructions exist; as it's forbidden in issuance
    for (const auto& inst : result->transferInstructions) {
        if (inst.skipInput) {
            throw std::runtime_error("An issuance script contained a skip transfer instruction: " +
                                     boost::algorithm::hex(ScriptBin));
        }
    }

    // the expected remaining byte is the issuance flag, otherwise a problem is there
    if (ScriptBin.size() != 1) {
        throw std::runtime_error(
            "Last expected byte is the issuance flag, but the remaining bytes are: " +
            boost::algorithm::hex(ScriptBin) + ", starting from " + boost::algorithm::hex(ScriptBin));
    }

    result->issuanceFlags = IssuanceFlags::ParseIssuanceFlag(ScriptBin.at(0));
    return result;
}

std::string NTP1Script_Issuance::getTokenID(std::string input0txid, unsigned int input0index) const
{
    // txid should be lower case
    std::transform(input0txid.begin(), input0txid.end(), input0txid.begin(), ::tolower);

    std::string tohash = input0txid + ":" + std::to_string(input0index);

    std::vector<unsigned char> sha256_result(32);
    std::vector<unsigned char> rip160_result(20);
    SHA256(reinterpret_cast<unsigned char*>(&tohash.front()), tohash.size(), &sha256_result.front());
    RIPEMD160(&sha256_result.front(), sha256_result.size(), &rip160_result.front());

    // get padded divisibility
    std::string divisibilityHex = ToHexString(getDivisibility(), false);
    if (divisibilityHex.size() > 4) {
        throw std::runtime_error("Divisibility hex value has more than 4 digits for token " +
                                 getTokenSymbol());
    }
    divisibilityHex             = std::string(4 - divisibilityHex.size(), '0') + divisibilityHex;
    std::string divisibilityBin = boost::algorithm::unhex(divisibilityHex);

    // aggregation policy and lock status
    std::string aggregatableHex = __getAggregAndLockStatusTokenIDHexValue();
    std::string aggregatableBin = boost::algorithm::unhex(aggregatableHex);

    std::vector<unsigned char> toBase58Check;
    toBase58Check.insert(toBase58Check.end(), aggregatableBin.begin(), aggregatableBin.end());
    toBase58Check.insert(toBase58Check.end(), rip160_result.begin(), rip160_result.end());
    toBase58Check.insert(toBase58Check.end(), divisibilityBin.begin(), divisibilityBin.end());

    std::string result = EncodeBase58Check(toBase58Check);

    return result;
}