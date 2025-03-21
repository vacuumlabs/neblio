#ifndef SENDCOINSENTRY_H
#define SENDCOINSENTRY_H

#include <QFrame>

namespace Ui {
class SendCoinsEntry;
}
class WalletModel;
class SendCoinsRecipient;

/** A single entry in the dialog for sending bitcoins. */
class SendCoinsEntry : public QFrame
{
    Q_OBJECT

public:
    explicit SendCoinsEntry(QWidget* parent, bool enableNTP1Tokens);
    ~SendCoinsEntry();

    void updateNTP1TokensList();

    void               setModel(WalletModel* modelIn);
    bool               validate();
    SendCoinsRecipient getValue();
    bool               isNTP1TokenSelected() const;

    /** Return whether the entry is still empty and unedited */
    bool isClear();

    void setValue(const SendCoinsRecipient& value);

    /** Set up the tab chain manually, as Qt messes up the tab chain by default in some cases (issue
     * https://bugreports.qt-project.org/browse/QTBUG-10907).
     */
    QWidget* setupTabChain(QWidget* prev);

    void setFocus();

public slots:
    void setRemoveEnabled(bool enabled);
    void clear();

signals:
    void removeEntry(SendCoinsEntry* entry);
    void payAmountChanged();

private slots:
    void on_deleteButton_clicked();
    void on_payTo_textChanged(const QString& address);
    void on_addressBookButton_clicked();
    void on_pasteButton_clicked();
    void updateDisplayUnit();

private:
    Ui::SendCoinsEntry* ui;
    WalletModel*        model;
};

#endif // SENDCOINSENTRY_H
