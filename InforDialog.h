#pragma once

#include <QWidget>
#include "ui_InforDialog.h"

class InforDialog : public QWidget
{
	Q_OBJECT

public:
	InforDialog(QWidget *parent = Q_NULLPTR);
	~InforDialog();
public:
	Ui::InforDialog ui;
};
