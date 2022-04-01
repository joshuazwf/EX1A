#include "QtWidgetsApplication1.h"
#include<QMessageBox>
#include"InforDialog.h"
#include<QDebug>
#include<QScrollBar>

#pragma execution_character_set("utf-8")

std::vector<infor> QtWidgetsApplication1::v;
QStandardItemModel* QtWidgetsApplication1::model;

//对界面中的相关控件进行操作
//这是对界面的一个初始化函数，构造初始的界面
QtWidgetsApplication1::QtWidgetsApplication1(QWidget *parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);
    //点击开始抓包之后，进行相关操作
    /*
    connect(ui.pushButton, &QPushButton::clicked, this, [=]() {
        //接收用户输入

        });
    connect(ui.pushButton_2, &QPushButton::clicked, this, [=]() {
   
        });
    */
    connect(ui.tableView, SIGNAL(doubleClicked(const QModelIndex&)), this,SLOT(onTableClicked(const QModelIndex&)));
    //connect(ui.tableView->verticalScrollBar(), SIGNAL(valueChanged(int)), this, SLOT(acceptVScrollValueChanged(int)));
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
    //获取当前的协议类型，如果是TCP则进行追踪
    QModelIndex indextemp2 = modessl->index(cur_index, 3);
    QVariant datatemp2 = modessl->data(indextemp2);
    QModelIndex indextemp3 = modessl->index(cur_index, 1);
    QVariant datatemp3 = modessl->data(indextemp3);
    QModelIndex indextemp4 = modessl->index(cur_index, 2);
    QVariant datatemp4 = modessl->data(indextemp4);
    QString src = datatemp3.toString();
    QString dst = datatemp4.toString();
    if (datatemp2.toString() == "TCP"|| datatemp2.toString() == "TLS"|| datatemp2.toString() == "HTTP") {
        QString res;
        int cnt = 0;
        qDebug() << "TCP" << "123";
        for (int i = 0;i < v.size();i++) {
            qDebug() << "TCP" << "123";
            if (v[i].ip_src == src && v[i].dst_ip == dst || v[i].ip_src == dst && v[i].dst_ip == src) {
                cnt++;
                res +="Time:"+ v[i].time +  "    IP_SRC:"+v[i].ip_src  + "    DST_IP:"+v[i].dst_ip  + "    Length:"+v[i].Length  +"     ProtoType:"+v[i].protocol+"\n\n";
            }
        }
        res = QString::number(cnt) + " TCP streams in total\n\n"+res;
        ide->ui.textBrowser_3->setText(res);
    }
    ide->ui.textBrowser->setText(datatemp.toString());
    ide->ui.textBrowser_2->setText(datatemp1.toString());
    ide->show();
}

void QtWidgetsApplication1::acceptVScrollValueChanged(int value){
    /*
    for (int i = 0;i < value;i++) {
        model->removeRow(value);
    }
    */
}


