#pragma once

#include <QWidget>
#include "ui_MainDialogClass.h"

class MainDialogClass : public QWidget
{
	Q_OBJECT

public:
	MainDialogClass(QWidget *parent = Q_NULLPTR);
	~MainDialogClass();

public:
	Ui::MainDialogClass ui;
	QString filter_m="";
	int choice_m=-1;
};
