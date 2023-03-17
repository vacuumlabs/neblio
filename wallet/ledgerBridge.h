#include "ledger/tx.h"
#include "ledger/bytes.h"

#include "wallet.h"
#include "script.h"

#include <vector>

namespace ledgerbridge
{
    struct LedgerBridgeUtxo
    {
        CTransaction transaction;
        uint32_t outputIndex;
        CScript outputPubKey;
    };

    class LedgerBridge
    {
        public:
            LedgerBridge();
            ~LedgerBridge();
            
            void SignTransaction(CWalletTx &wtxNew, const std::vector<LedgerBridgeUtxo> &utxos);
        private:
            ledger::Tx ToLedgerTx(const CTransaction& tx);
    };
}