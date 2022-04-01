#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_QtWidgetsApplication1.h"
#include "Network_Packet.h"
#include<QStandardItemModel>


class infor {
public:
    QString time;
    QString ip_src;
    QString dst_ip;
    QString Length;
    QString ALL;
    QString protocol;
    QString more;
};

class QtWidgetsApplication1 : public QMainWindow
{
    Q_OBJECT
public:
    QtWidgetsApplication1(QWidget *parent = Q_NULLPTR);
public:
    Ui::QtWidgetsApplication1Class ui;
    static std::vector<infor> v;
    static QStandardItemModel* model;
private slots:
     void onTableClicked(const QModelIndex& index);
     void acceptVScrollValueChanged(int value);
};






