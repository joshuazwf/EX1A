#include "QtWidgetsApplication1.h"
#include<QMessageBox>
#include"InforDialog.h"
#include<QDebug>

#pragma execution_character_set("utf-8")

//�Խ����е���ؿؼ����в���
//���ǶԽ����һ����ʼ�������������ʼ�Ľ���
QtWidgetsApplication1::QtWidgetsApplication1(QWidget *parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);
    //�����ʼץ��֮�󣬽�����ز���
    connect(ui.pushButton, &QPushButton::clicked, this, [=]() {
        //�����û�����

        });
    connect(ui.pushButton_2, &QPushButton::clicked, this, [=]() {
   
        });

    connect(ui.tableView, SIGNAL(doubleClicked(const QModelIndex&)), SLOT(onTableClicked(const QModelIndex&)));
}

void QtWidgetsApplication1::onTableClicked(const QModelIndex& index) {
    //��������Ŀ���
    InforDialog* ide = new InforDialog();
    int cur_index = ui.tableView->currentIndex().row();
    QAbstractItemModel* modessl = ui.tableView->model();
    QModelIndex indextemp = modessl->index(cur_index,6);
    QVariant datatemp = modessl->data(indextemp);
    QModelIndex indextemp1 = modessl->index(cur_index, 5);
    QVariant datatemp1 = modessl->data(indextemp1);
    ide->ui.textBrowser->setText(datatemp.toString());
    ide->ui.textBrowser_2->setText(datatemp1.toString()); 
    ide->show();//��������ָ��ķ���������
}


