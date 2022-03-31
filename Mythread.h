#pragma once
#include<QThread>

class MyThread :public QThread
{
public:
    void run();
    ~MyThread() {
        wait();
    }
};

