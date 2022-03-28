#include "QtWidgetsApplication1.h"
#include<QMessageBox>
#include<QStandardItemModel>
#include"InforDialog.h"
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
        QMessageBox::information(this, "srds", "sdsd");
        });
    connect(ui.tableView, SIGNAL(doubleClicked(const QModelIndex&)), SLOT(onTableClicked(const QModelIndex&)));
}

void QtWidgetsApplication1::onTableClicked(const QModelIndex& index) {
    int cur_index = ui.tableView->currentIndex().row();
    QAbstractItemModel* modessl = ui.tableView->model();
    QModelIndex indextemp = modessl->index(cur_index,1);
    QVariant datatemp = modessl->data(indextemp);
    //QMessageBox::information(this, "Frame", datatemp.toString());
    InforDialog* ide=new InforDialog();
    //ide->ui.setupUi(ide);
    ide->ui.textBrowser->setText(datatemp.toString());
    ide->show();//这样采用指针的方法不会闪现
}
