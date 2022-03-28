#include "QtWidgetsApplication1.h"
#include<QMessageBox>
#include<QStandardItemModel>
#include"InforDialog.h"
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
    ide->show();//��������ָ��ķ�����������
}
