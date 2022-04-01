#include "Network_Packet.h"
Network_Packet::Network_Packet(char* sfilter) {
	filter = sfilter;
	alldevs = nullptr;
	handler = nullptr;
	dev_num = 0;
}

void Network_Packet::getInterfaces() {
	pcap_if_t* d;
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		fprintf(stderr, "Error inpcap_findalldevs: %s\n", errbuf);
	}
	//输出各个网卡的描述
	for (d = alldevs;d;d = d->next) {
		dev_num++;
	}
}

void Network_Packet::choose_inter(int choice) {
	if (dev_num==4)
		choice = 2;//本机是二号网卡有包
	if (dev_num == 5)
		choice = 3;
	if (choice<1 || choice>dev_num) {
		pcap_freealldevs(alldevs);
	}
	pcap_if_t* d= alldevs->next;
	int i = 0;
	//根据用户的输入，通过指针进行找寻到当前网卡
	//Realtek PCIe GbE Family Controller
	for (d = alldevs, i = 0;i < choice;i++, d = d->next) {
		description = d->description;
	}
	//description = d->description;
	/* d->name to hand to "pcap_open_live()" */
	/*值65535应该足以捕获数据包中可用的所有数据*/
	/*将该设备设置到混杂模式，用于监听*/
	/*错误信息提示*/
	char errbuf[PCAP_ERRBUF_SIZE];
	handler = pcap_open_live(d->name, (int)65536, 1, 1000, errbuf);
	//表示没有打开成功
	if (handler == NULL) {
		pcap_freealldevs(alldevs);
	}
	int res = pcap_datalink(handler);
	
	//目前处理的链路层的协议是 以太网的协议
	if (res != DLT_EN10MB) {
		pcap_freealldevs(alldevs);
	}
	bpf_u_int32 netmask;
	if (d->addresses != NULL) {
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	}
	else {
		/* 如果这个接口没有地址那么我们假设他为C类地址 */
		netmask = 0xffffff;
	}
	//Structure for "pcap_compile()", "pcap_setfilter()", etc..
	struct bpf_program fcode;
	int res_compile = pcap_compile(handler, &fcode, filter, 1, netmask);
	if (res_compile < 0) {
		pcap_freealldevs(alldevs);
		exit(-1);
	}
	if (pcap_setfilter(handler, &fcode) < 0) {
		pcap_freealldevs(alldevs);
	}
	pcap_freealldevs(alldevs);
}



