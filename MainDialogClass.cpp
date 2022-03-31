#include "MainDialogClass.h"

MainDialogClass::MainDialogClass(QWidget *parent)
	: QWidget(parent)
{
	ui.setupUi(this);
	connect(ui.pushButton, &QPushButton::clicked, this, [=]() {
		filter_m = ui.lineEdit->text();
		choice_m = ui.comboBox->currentIndex() + 1;
		});
}

MainDialogClass::~MainDialogClass()
{
}
