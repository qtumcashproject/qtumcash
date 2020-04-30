#ifndef QTHPUSHBUTTON_H
#define QTHPUSHBUTTON_H
#include <QPushButton>
#include <QStyleOptionButton>
#include <QIcon>

class QtumCashPushButton : public QPushButton
{
public:
    explicit QtumCashPushButton(QWidget * parent = Q_NULLPTR);
    explicit QtumCashPushButton(const QString &text, QWidget *parent = Q_NULLPTR);

protected:
    void paintEvent(QPaintEvent *) Q_DECL_OVERRIDE;

private:
    void updateIcon(QStyleOptionButton &pushbutton);

private:
    bool m_iconCached;
    QIcon m_downIcon;
};

#endif // QTHPUSHBUTTON_H
