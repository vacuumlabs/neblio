#include "ledger/tx.h"
#include "ledger/bytes.h"

#include "itxdb.h"
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
            
            ledger::bytes GetPublicKey(const std::string& path, bool display);
            ledger::bytes GetPublicKey(int account, int index, bool display);
            void SignTransaction(const ITxDB& txdb, const CWallet& wallet, CWalletTx &wtxNew, const std::vector<LedgerBridgeUtxo> &utxos);
        private:
            ledger::Tx ToLedgerTx(const CTransaction& tx);
    };
}
