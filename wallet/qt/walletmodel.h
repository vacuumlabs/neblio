#ifndef WALLETMODEL_H
#define WALLETMODEL_H

#include <QObject>
#include <QSharedPointer>
#include <QThread>
#include <map>
#include <vector>

#include "ntp1/ntp1wallet.h"

#include "allocators.h" /* for SecureString */

class WalletModel;
class OptionsModel;
class AddressTableModel;
class TransactionTableModel;
class CWallet;
class CKeyID;
class CPubKey;
class COutput;
class COutPoint;
class uint256;
class CCoinControl;

QT_BEGIN_NAMESPACE
class QTimer;
QT_END_NAMESPACE

class SendCoinsRecipient
{
public:
    QString address;
    QString label;
    QString tokenId;
    qint64  amount;
};

class BalancesWorker : public QObject
{
    Q_OBJECT

public slots:
    // we use the shared pointer argument to ensure that workerPtr will be deleted after doing the
    // retrieval
    void getBalances(WalletModel* walletModel, QSharedPointer<BalancesWorker> workerPtr);

signals:
    // Signal that balance in wallet changed
    void resultReady(qint64 balance, qint64 stake, qint64 unconfirmedBalance, qint64 immatureBalance);
};

/** Interface to Bitcoin wallet from Qt view code. */
class WalletModel : public QObject
{
    Q_OBJECT

public:
    explicit WalletModel(CWallet* walletIn, OptionsModel* optionsModelIn, QObject* parent = 0);
    ~WalletModel();

    enum StatusCode // Returned by sendCoins
    {
        OK,
        InvalidAmount,
        InvalidAddress,
        AmountExceedsBalance,
        AmountWithFeeExceedsBalance,
        DuplicateAddress,
        TransactionCreationFailed, // Error returned when wallet is still locked
        TransactionCommitFailed,
        AddressContainsNTP1Tokens,
        AddressNTP1TokensCheckFailed,
        AddressNTP1TokensCheckFailedWrongNumberOfOutputs,
        AddressNTP1TokensCheckFailedTxNotFound,
        AddressNTP1TokensCheckFailedFailedToDecodeScriptPubKey,
        EmptyNTP1TokenID,
        NTP1TokenCalculationsFailed,
        Aborted
    };

    enum EncryptionStatus
    {
        Unencrypted, // !wallet->IsCrypted()
        Locked,      // wallet->IsCrypted() && wallet->IsLocked()
        Unlocked     // wallet->IsCrypted() && !wallet->IsLocked()
    };

    OptionsModel*          getOptionsModel();
    AddressTableModel*     getAddressTableModel();
    TransactionTableModel* getTransactionTableModel();

    qint64                    getBalance() const;
    qint64                    getStake() const;
    qint64                    getUnconfirmedBalance() const;
    qint64                    getImmatureBalance() const;
    boost::optional<uint64_t> getNumTransactions() const;
    EncryptionStatus          getEncryptionStatus() const;

    // Check address for validity
    bool validateAddress(const QString& address);

    // Return status record for SendCoins, contains error id + information
    struct SendCoinsReturn
    {
        SendCoinsReturn(StatusCode statusIn = Aborted, qint64 feeIn = 0, QString hexIn = QString())
            : status(statusIn), fee(feeIn), hex(hexIn)
        {
        }
        StatusCode status;
        qint64     fee; // is used in case status is "AmountWithFeeExceedsBalance"
        QString    hex; // is filled with the transaction hash if status is "OK"
        QString
            address; // is filled with address if a problem with an address exists (due to NTP1 tokens)
        QString msg; // error message, if necessary
    };

    // Send coins to a list of recipients
    SendCoinsReturn sendCoins(QList<SendCoinsRecipient>        recipients,
                              boost::shared_ptr<NTP1Wallet>    ntp1wallet,
                              const RawNTP1MetadataBeforeSend& ntp1metadata, bool fSpendDelegated,
                              const CCoinControl* coinControl   = nullptr,
                              const std::string& strFromAccount = "", bool fLedgerTx = false);

    // Wallet encryption
    bool setWalletEncrypted(bool encrypted, const SecureString& passphrase);
    // Passphrase only needed when unlocking
    bool setWalletLocked(bool locked, const SecureString& passPhrase = SecureString());
    bool changePassphrase(const SecureString& oldPass, const SecureString& newPass);
    // Wallet backup
    bool backupWallet(const QString& filename);

    // RAI object for unlocking wallet, returned by requestUnlock()
    class UnlockContext
    {
    public:
        UnlockContext(WalletModel* walletIn, bool validIn, bool relockIn);
        ~UnlockContext();

        bool isValid() const { return valid; }

        // Copy operator and constructor transfer the context
        UnlockContext(const UnlockContext& obj) { CopyFrom(obj); }
        UnlockContext& operator=(const UnlockContext& rhs)
        {
            CopyFrom(rhs);
            return *this;
        }

    private:
        WalletModel* wallet;
        bool         valid;
        mutable bool relock; // mutable, as it can be set to false by copying

        void CopyFrom(const UnlockContext& rhs);
    };

    UnlockContext requestUnlock();

    bool getPubKey(const CKeyID& address, CPubKey& vchPubKeyOut) const;
    bool getLedgerKey(const CKeyID& address, CLedgerKey& ledgerKeyOut) const;
    void getOutputs(const std::vector<COutPoint>& vOutpoints, std::vector<COutput>& vOutputs);
    void listCoins(std::map<QString, std::vector<COutput>>& mapCoins) const;
    bool isLockedCoin(uint256 hash, unsigned int n) const;
    void lockCoin(COutPoint& output);
    void unlockCoin(COutPoint& output);
    void listLockedCoins(std::vector<COutPoint>& vOutpts);

    bool        whitelistAddressFromColdStaking(const QString& addressStr);
    bool        blacklistAddressFromColdStaking(const QString& address);
    bool        updateAddressBookPurpose(const QString& addressStr, const std::string& purpose);
    std::string getLabelForAddress(const CBitcoinAddress& address);
    bool        getKeyId(const CBitcoinAddress& address, CKeyID& keyID);

    CWallet* getWallet();

    int64_t getCreationTime() const;

    void checkBalanceChanged();

    QThread* getBalancesThread();

private:
    CWallet* wallet;

    QThread balancesThread;
    bool    isBalancesWorkerRunning  = false;
    bool    isBalanceWorkerScheduled = false;

    // Wallet has an options model for wallet-specific options
    // (transaction fee, for example)
    OptionsModel* optionsModel;

    AddressTableModel*     addressTableModel;
    TransactionTableModel* transactionTableModel;

    // Cache some values to be able to detect changes
    bool             firstUpdateOfBalanceDone = false;
    qint64           cachedBalance;
    qint64           cachedStake;
    qint64           cachedUnconfirmedBalance;
    qint64           cachedImmatureBalance;
    quint64          cachedNumTransactions;
    EncryptionStatus cachedEncryptionStatus;
    int              cachedNumBlocks;

    QTimer* pollTimer;

    void subscribeToCoreSignals();
    void unsubscribeFromCoreSignals();
public slots:
    /* Wallet status might have changed */
    void updateStatus();
    /* New transaction, or transaction changed status */
    void updateTransaction(const QString& hash, int status);
    /**/
    void updateNumTransactions();
    /* New, updated or removed address book entry */
    void updateAddressBook(const QString& address, const QString& label, uint isMine,
                           const QString& purpose, int status);
    /* Current, immature or unconfirmed balance might have changed - emit 'balanceChanged' if so */
    void pollBalanceChanged();

    void updateBalancesIfChanged(qint64 newBalance, qint64 newStake, qint64 newUnconfirmedBalance,
                                 qint64 newImmatureBalance);

signals:
    // Signal that balance in wallet changed
    void balanceChanged(qint64 balance, qint64 stake, qint64 unconfirmedBalance, qint64 immatureBalance);

    // Number of transactions in wallet changed
    void numTransactionsChanged(int count);

    // Encryption status of wallet changed
    void encryptionStatusChanged(int status);

    // Signal emitted when wallet needs to be unlocked
    // It is valid behaviour for listeners to keep the wallet locked after this signal;
    // this means that the unlocking failed or was cancelled.
    void requireUnlock();

    // Asynchronous error notification
    void error(const QString& title, const QString& message, bool modal);
};

#endif // WALLETMODEL_H
