#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_QtWidgetsApplication1.h"

class QtWidgetsApplication1 : public QMainWindow
{
    Q_OBJECT
public:
    QtWidgetsApplication1(QWidget *parent = Q_NULLPTR);
public:
    Ui::QtWidgetsApplication1Class ui;
    static QString infor;
private slots:
     void onTableClicked(const QModelIndex& index);
};
