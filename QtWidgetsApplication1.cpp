#include "QtWidgetsApplication1.h"
#include<QMessageBox>
#include"InforDialog.h"
#include<QDebug>

#pragma execution_character_set("utf-8")

//对界面中的相关控件进行操作
//这是对界面的一个初始化函数，构造初始的界面
QtWidgetsApplication1::QtWidgetsApplication1(QWidget *parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);
    //点击开始抓包之后，进行相关操作
    connect(ui.pushButton, &QPushButton::clicked, this, [=]() {
        //接收用户输入

        });
    connect(ui.pushButton_2, &QPushButton::clicked, this, [=]() {
   
        });

    connect(ui.tableView, SIGNAL(doubleClicked(const QModelIndex&)), SLOT(onTableClicked(const QModelIndex&)));
}

void QtWidgetsApplication1::onTableClicked(const QModelIndex& index) {
    //存在溢出的可能
    InforDialog* ide = new InforDialog();
    int cur_index = ui.tableView->currentIndex().row();
    QAbstractItemModel* modessl = ui.tableView->model();
    QModelIndex indextemp = modessl->index(cur_index,6);
    QVariant datatemp = modessl->data(indextemp);
    QModelIndex indextemp1 = modessl->index(cur_index, 5);
    QVariant datatemp1 = modessl->data(indextemp1);
    ide->ui.textBrowser->setText(datatemp.toString());
    ide->ui.textBrowser_2->setText(datatemp1.toString()); 
    ide->show();//这样采用指针的方法不会闪
}


