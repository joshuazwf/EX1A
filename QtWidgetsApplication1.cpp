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
    //��������Ŀ���
    int cur_index = ui.tableView->currentIndex().row();
    QAbstractItemModel* modessl = ui.tableView->model();
    QModelIndex indextemp = modessl->index(cur_index,6);
    QVariant datatemp = modessl->data(indextemp);
    
    InforDialog* ide = new InforDialog();
    ide->ui.textBrowser->setText(datatemp.toString());
    //ide->ui.textBrowser->setText("ssdddddddddddddd");
    ide->show();//��������ָ��ķ�����������
}
