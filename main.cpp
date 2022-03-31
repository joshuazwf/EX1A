#include "QtWidgetsApplication1.h"
#include <QtWidgets/QApplication>
#include<QStandardItemModel>
#include "Network_Packet.h"
#include<QDebug>
#include<QJsonObject>
#include<QJsonDocument>
#include<vector>
#include<QJsonArray>
#include<QThread>
#include<Windows.h>
#include <QtConcurrent/QtConcurrent>
#include "MainDialogClass.h"

#pragma execution_character_set("utf-8")


//time source destnation length info
Network_Packet sniffer;
QString g_time, g_source, g_dest, g_length, g_protocol, g_pkt_str;
QStandardItemModel* model;
long long g_number = 0;//防止溢出 因为包的数量是巨大的
int g_packet_len;


void data_link_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
std::vector<QString> net4_layer_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
std::vector<QString> net6_layer_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
QString arp_pck(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
std::vector<QString> Transmission_tcp_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
QString Transmission_udp_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
QString TLS_layer_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);


void data_link_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    //获取当前包的时间
    //Frame 79: 1294 bytes on wire (10352 bits),
    //1294 bytes captured (10352 bits) on interface \Device\NPF_{64E89EF2-0BB1-4C7A-B75F-8D6599A35C17}, id 0
    struct tm ltime;
    char timestr[16];
    time_t local_tv_sec;
    (VOID)(param);
    /* convert the timestamp to readable format */
    local_tv_sec = header->ts.tv_sec;
    //header->caplen;
    bpf_u_int32 cap_len = header->caplen;
    ////将整个数据包采用十六进制的方式全部表示出来
    for (int i = 1;i < cap_len + 1;i++) {
        g_pkt_str += QString("%1").arg(pkt_data[i - 1], 2, 16, QLatin1Char('0')) + "  ";
        if (i % 16 == 0) {
            g_pkt_str += "\n";
        }
    }
    //qDebug() <<"all len:"<<g_pkt_str;
    bpf_u_int32 len = header->len;//
    localtime_s(&ltime, &local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);
    //对以太网的帧进行分析
    u_short type;
    ethernet_header* E_header = (ethernet_header*)pkt_data;
    QString s = "";
    QString first = QString("%1").arg(E_header->src_mac.first, 2, 16, QLatin1Char('0'));
    QString second = QString("%1").arg(E_header->src_mac.second, 2, 16, QLatin1Char('0'));
    QString third = QString("%1").arg(E_header->src_mac.third, 2, 16, QLatin1Char('0'));
    QString four = QString("%1").arg(E_header->src_mac.four, 2, 16, QLatin1Char('0'));
    QString five = QString("%1").arg(E_header->src_mac.five, 2, 16, QLatin1Char('0'));
    QString six = QString("%1").arg(E_header->src_mac.six, 2, 16, QLatin1Char('0'));
    QString first_1 = QString("%1").arg(E_header->dst_mac.first, 2, 16, QLatin1Char('0'));
    QString second_1 = QString("%1").arg(E_header->dst_mac.second, 2, 16, QLatin1Char('0'));
    QString third_1 = QString("%1").arg(E_header->dst_mac.third, 2, 16, QLatin1Char('0'));
    QString four_1 = QString("%1").arg(E_header->dst_mac.four, 2, 16, QLatin1Char('0'));
    QString five_1 = QString("%1").arg(E_header->dst_mac.five, 2, 16, QLatin1Char('0'));
    QString six_1 = QString("%1").arg(E_header->dst_mac.six, 2, 16, QLatin1Char('0'));
    QString src_mac = first + ":" + second + ":" + third + ":" + four + ":" + five + ":" + six;
    QString dst_mac = first_1 + ":" + second_1 + ":" + third_1 + ":" + four_1 + ":" + five_1 + ":" + six_1;
    type = ntohs(E_header->type);
    QString T_type;
    if (type == 0x0800) {
        T_type = "ipv4(0x0800)";
    }
    if (type == 0x86DD) {
        T_type = "ipv6(0x86DD)";
    }
    if (type == 0x0806) {
        T_type = "arp(0x0806)";
    }
    QString ether_infor = "Ethernet II,Src:" + src_mac + ", Dst:" + dst_mac
        + "\n" + "    Type:" + T_type + "\n";
    if (type == 0x0800) {
        std::vector<QString> re = net4_layer_handler(param, header, pkt_data + 14);
        for (int i = 0;i < re.size();i++) {
            ether_infor += "\n" + re[i];
        }
    }
    else if (type == 0x86DD) {
        net6_layer_handler(param, header, pkt_data + 14);
        std::vector<QString> re = net6_layer_handler(param, header, pkt_data + 14);
        for (int i = 0;i < re.size();i++) {
            ether_infor += "\n" + re[i];
        }
    }
    else if (type == 0x0806) {
        QString re = arp_pck(param, header, pkt_data + 14);
        ether_infor += "\n" + re;
    }
    else {
        //暂时不考虑
    }
    //ip地址一定是在第二层
    //g_time = QString(timestr);时间的显示采取
    g_time = QString::number(local_tv_sec);
    g_length = QString::number(len);
    g_packet_len = cap_len;
    QString physical = QString::number(cap_len) + " bytes on wires and " + g_length + " bytes captured on interface " + sniffer.description + "\n" + "\n";
    if (g_number + 1 < 0xffffffff) {
        model->setItem(g_number, 0, new QStandardItem(g_time));
        model->setItem(g_number, 1, new QStandardItem(g_source));
        model->setItem(g_number, 2, new QStandardItem(g_dest));
        model->setItem(g_number, 3, new QStandardItem(g_protocol));
        model->setItem(g_number, 4, new QStandardItem(g_length));
        model->setItem(g_number, 5, new QStandardItem("ALL DATA:\n" + g_pkt_str));
        model->setItem(g_number, 6, new QStandardItem(physical + ether_infor));
        g_number += 1; 
        //qApp->processEvents();
        //qApp->processEvents();
        Sleep(2000);
    }
    g_packet_len -= 14;
}

std::vector<QString> net4_layer_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    IPV4_Header* ip4_header = (IPV4_Header*)pkt_data;
    // ip4长度不定
    /** 1 ICMP * 2 IGMP* 6 TCP* 17 UDP*/
    QString src_ip = QString::number(ip4_header->src_ip.fisrt) + "." + QString::number(ip4_header->src_ip.second)
        + "." + QString::number(ip4_header->src_ip.third) + "." + QString::number(ip4_header->src_ip.fourth);
    QString dst_ip = QString::number(ip4_header->dst_ip.fisrt) + "." + QString::number(ip4_header->dst_ip.second)
        + "." + QString::number(ip4_header->dst_ip.third) + "." + QString::number(ip4_header->dst_ip.fourth);
    u_char version = (ip4_header->version_length) & (0xf0); //11110000
    version /= 16;
    u_int ip_len = ((ip4_header->version_length) & 0xf) * 4;
    g_packet_len -= ip_len;
    u_char tos = ntohs(ip4_header->type_of_service);
    u_short t_len = ntohs(ip4_header->total_len);
    u_short identifier = ntohs(ip4_header->identifier);
    u_short flags = (ntohs(ip4_header->flags_fragment)) & 0xe0000;//3位标志
    u_short fragment = (ntohs(ip4_header->flags_fragment)) & 0x1fff;//13位偏移
    u_char ttl = ip4_header->TTL;
    u_char protocol = (ip4_header->protocol);
    u_short check_sum = ntohs(ip4_header->header_sum);
    QString toss = QString("%1").arg(tos, 2, 16, QLatin1Char('0'));
    QString iden = QString("%1").arg(identifier, 2, 16, QLatin1Char('0'));
    QString b = QString("%1").arg(flags, 16, 2, QLatin1Char('0'));//转为2进制  16位填充
    QString flag = b.left(3);
    QString f = QString("%1").arg(fragment, 16, 2, QLatin1Char('0'));
    QString frag = f.right(13);
    QString pro;
    if (protocol == 6)
        pro = "tcp(6)";
    if (protocol == 17)
        pro = "udp(17)";
    if (protocol == 1)
        pro = "icmp(1)";
    QString sum = QString("%1").arg(check_sum, 2, 16, QLatin1Char('0'));
    std::vector<QString> res;
    //Internet Protocol Version 4, Src: 192.168.43.184, Dst: 40.77.226.250
    g_source = src_ip;
    g_dest = dst_ip;
    g_protocol = "ipv4";
    QString Ip4_infor = "Internet Protocol Version 4, Src:" + src_ip + ", Dst:" + dst_ip + "\n" +
        "    Version:" + QString::number(version) + "\n" + "    Header Length:" + QString::number(ip_len) + " bytes" + "\n"
        + "    Type of Service:" + "0x" + toss + "\n" + "    Total Length:" + QString::number(t_len) + "\n" +
        "    Identification:" + "0x" + iden + "\n" + "    flags[ReservedBit,Don't Fragment,More Fragment]:" + flag + "\n" +
        "    Fragment:" + frag + "\n" + "    Time to Live:" + QString::number(ttl) + "\n" + "    Protocol:" + pro + "\n    Check Sum:" + "0x" + sum + "\n";
    //ipv4字符串
    res.push_back(Ip4_infor);
    if (protocol == 6) {
        std::vector<QString> s = Transmission_tcp_handler(param, header, pkt_data + ip_len);
        for (int i = 0;i < s.size();i++)
            res.push_back(s[i]);
    }
    else if (protocol == 17) {
        QString re = Transmission_udp_handler(param, header, pkt_data + ip_len);
        res.push_back(re);
    }
    else if (protocol == 1) {
        //icmp_handler(param, header, pkt_data + ip_len);
    }
    else {
        //暂不考虑
    }
    return res;
}

std::vector<QString> net6_layer_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    IPV6_Header* ip6_header = (IPV6_Header*)pkt_data;
    QString s1 = QString("%1").arg(ip6_header->src_ip.first, 4, 16, QLatin1Char('0'));
    QString s2 = QString("%1").arg(ip6_header->src_ip.second, 4, 16, QLatin1Char('0'));
    QString s3 = QString("%1").arg(ip6_header->src_ip.third, 4, 16, QLatin1Char('0'));
    QString s4 = QString("%1").arg(ip6_header->src_ip.fourth, 4, 16, QLatin1Char('0'));
    QString s5 = QString("%1").arg(ip6_header->src_ip.five, 4, 16, QLatin1Char('0'));
    QString s6 = QString("%1").arg(ip6_header->src_ip.six, 4, 16, QLatin1Char('0'));
    QString s7 = QString("%1").arg(ip6_header->src_ip.seven, 4, 16, QLatin1Char('0'));
    QString s8 = QString("%1").arg(ip6_header->src_ip.eight, 4, 16, QLatin1Char('0'));
    QString d1 = QString("%1").arg(ip6_header->dst_ip.first, 4, 16, QLatin1Char('0'));
    QString d2 = QString("%1").arg(ip6_header->dst_ip.second, 4, 16, QLatin1Char('0'));
    QString d3 = QString("%1").arg(ip6_header->dst_ip.third, 4, 16, QLatin1Char('0'));
    QString d4 = QString("%1").arg(ip6_header->dst_ip.fourth, 4, 16, QLatin1Char('0'));
    QString d5 = QString("%1").arg(ip6_header->dst_ip.five, 4, 16, QLatin1Char('0'));
    QString d6 = QString("%1").arg(ip6_header->dst_ip.six, 4, 16, QLatin1Char('0'));
    QString d7 = QString("%1").arg(ip6_header->dst_ip.seven, 4, 16, QLatin1Char('0'));
    QString d8 = QString("%1").arg(ip6_header->dst_ip.eight, 4, 16, QLatin1Char('0'));
    QString src6_ip = s1 + ":" + s2 + ":" + s3 + ":" + s4 + ":" + s5 + ":" + s6 + ":" + s7 + ":" + s8;
    QString dst6_ip = d1 + ":" + d2 + ":" + d3 + ":" + d4 + ":" + d5 + ":" + d6 + ":" + d7 + ":" + d8;
    g_source = src6_ip;
    g_dest = dst6_ip;
    g_protocol = "ipv6";
    g_packet_len -= 40;
    QString b = QString("%1").arg(ntohs(ip6_header->ver_flow_label), 32, 2, QLatin1Char('0'));//转为2进制  16位填充
    QString traffic_class = b.right(28).left(8);
    QString DFS = b.right(28).left(6);
    QString ECN = b.right(22).left(2);
    QString flow = QString("%1").arg(ntohs(ip6_header->ver_flow_label) & (0x000fffff), 5, 16, QLatin1Char('0'));
    QString pro;
    if (ip6_header->next == 6)
        pro = "tcp(6)";
    if (ip6_header->next == 17)
        pro = "udp(17)";
    if (ip6_header->next == 1)
        pro = "icmp(1)";
    std::vector<QString> v;
    QString ip6_infor = "Internet Protocol Version 6, Src:" + src6_ip + ", Dst: " + dst6_ip + "\n" +
        "    Version:6" + "\n" + "    Traffic Class:" + traffic_class + "\n" + "    Differentiated Services Codepoint : " + DFS + "\n" +
        "    Explicit Congestion Notification:" + ECN + "\n" + "    Flow Label:0x" +
        flow + "\n" + "    PayLoad Length:" + QString::number(ip6_header->data_len) + "\n" + "    Next Header:" + pro + "\n" + "    Hop Limit:"
        + QString::number(ip6_header->limit) + "\n";
    v.push_back(ip6_infor);
    if (ip6_header->next == 6) {
        std::vector<QString> tcp_r = Transmission_tcp_handler(param, header, pkt_data + 40);
        for (int i = 0;i < tcp_r.size();i++)
            v.push_back(tcp_r[i]);
    }
    if (ip6_header->next == 17) {
        QString re = Transmission_udp_handler(param, header, pkt_data + 40);
        v.push_back(re);
    }
    if (ip6_header->next == 1) {
        // icmp_handler(param, header, pkt_data + 40);
    }
    return v;
}

QString arp_pck(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    g_protocol = "ARP";
    ARP* arp_h = (ARP*)pkt_data;
    QString arp_t = QString::number(ntohs(arp_h->hard_type));
    QString pro_t = QString::number(ntohs(arp_h->pro_type));
    QString hard_s = QString::number(ntohs(arp_h->hard_len));
    QString pro_s = QString::number(ntohs(arp_h->pro_len));
    QString op_c = QString::number(ntohs(arp_h->op_type));
    QString first = QString("%1").arg(arp_h->src_mac.first, 2, 16, QLatin1Char('0'));
    QString second = QString("%1").arg(arp_h->src_mac.second, 2, 16, QLatin1Char('0'));
    QString third = QString("%1").arg(arp_h->src_mac.third, 2, 16, QLatin1Char('0'));
    QString four = QString("%1").arg(arp_h->src_mac.four, 2, 16, QLatin1Char('0'));
    QString five = QString("%1").arg(arp_h->src_mac.five, 2, 16, QLatin1Char('0'));
    QString six = QString("%1").arg(arp_h->src_mac.six, 2, 16, QLatin1Char('0'));
    QString first_1 = QString("%1").arg(arp_h->dst_mac.first, 2, 16, QLatin1Char('0'));
    QString second_1 = QString("%1").arg(arp_h->dst_mac.second, 2, 16, QLatin1Char('0'));
    QString third_1 = QString("%1").arg(arp_h->dst_mac.third, 2, 16, QLatin1Char('0'));
    QString four_1 = QString("%1").arg(arp_h->dst_mac.four, 2, 16, QLatin1Char('0'));
    QString five_1 = QString("%1").arg(arp_h->dst_mac.five, 2, 16, QLatin1Char('0'));
    QString six_1 = QString("%1").arg(arp_h->dst_mac.six, 2, 16, QLatin1Char('0'));
    QString src_mac = first + ":" + second + ":" + third + ":" + four + ":" + five + ":" + six;
    QString dst_mac = first_1 + ":" + second_1 + ":" + third_1 + ":" + four_1 + ":" + five_1 + ":" + six_1;
    QString src_ip = QString::number(arp_h->src_ip.fisrt) + "." + QString::number(arp_h->src_ip.second)
        + "." + QString::number(arp_h->src_ip.third) + "." + QString::number(arp_h->src_ip.fourth);
    QString dst_ip = QString::number(arp_h->dst_ip.fisrt) + "." + QString::number(arp_h->dst_ip.second)
        + "." + QString::number(arp_h->dst_ip.third) + "." + QString::number(arp_h->dst_ip.fourth);
    g_source = src_ip;
    g_dest = dst_ip;
    QString arp_infor = "Address Resolution Protocol\n";
    arp_infor += "    Hardware Type:" + arp_t + "\n" + "    Protocol Type:" + pro_t + "\n" +
        "    HardwWare Size:" + hard_s + "\n" + "    Protocol Size:" + pro_s + "\n" + "    Opcode:" + op_c + "\n" + "    Sender Mac Address:" +
        src_mac + "\n" + "    Sender IP Address:" + src_ip + "\n" + "    Receiver Mac Address: " + dst_mac + "\n" +
        "    Receiver IP Address:" + dst_ip + "\n";
    //得到ARP的各个字段
    return arp_infor;
}

std::vector<QString> Transmission_tcp_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    g_protocol = "TCP";
    TCP_header* tcp_header = (TCP_header*)pkt_data;
    QString ack = QString::number(ntohs(tcp_header->ack));
    QString seq = QString::number(ntohs(tcp_header->seq));
    //获得端口号
    u_short dst_port = ntohs(tcp_header->dst_port);
    QString s_dst_port = QString::number(dst_port);
    u_short src_port = ntohs(tcp_header->src_port);
    QString s_src_port = QString::number(src_port);
    u_short head_len = (ntohs(tcp_header->len_keep_flag)) & 0xf000;
    head_len = head_len >> 12;
    QString s_head_len = QString::number(head_len);
    QString win_size = QString::number(ntohs(tcp_header->win_size));
    QString d1 = "0x" + QString("%1").arg(ntohs(tcp_header->check_sum), 4, 16, QLatin1Char('0'));
    QString urgent = QString::number(ntohs(tcp_header->urgency));
    u_short flag = (ntohs(tcp_header->len_keep_flag)) & 0x0fff;
    QString s_flag = "0x" + QString("%1").arg(flag, 4, 16, QLatin1Char('0'));
    std::vector<QString> v;
    //Transmission Control Protocol, Src Port: 80 Dst Port: 53565, Seq: 1, Ack: 404, Len: 90
    QString tcp_infor = "Transmission Control Protocol, Src Port: " + s_src_port + " Dst Port:" + s_dst_port + ", Seq:" + seq + ",ACK:" + ack + "\n";
    tcp_infor += "    Scouce Port:" + s_src_port + "\n" + "    Dst Port:" + s_dst_port + "\n" +
        "    Header Length:" + s_head_len + "\n" + "    Flags:" + s_flag + "\n" + "    WindowSize:" + win_size + "\n" +
        "    CheckSum:" + d1 + "\n" + "    Urgent:" + urgent;

    //此时减去每一层的长度之后，那么如果依然存在数据包的长度时，则可以判断存在应用层的数据;e否则，就是TCP报文的SYN/FIN
    //HTTP 应用层协议
    v.push_back(tcp_infor);
    if (g_packet_len - head_len == 0)
        return v;
    if (dst_port == 80 || src_port == 80) {
        g_protocol = "HTTP";
        qDebug() << "HTTP" << QString((char*)pkt_data + head_len);
        qDebug() << QString::fromLocal8Bit((char*)pkt_data + head_len);
        //QString http=HTTP_layer_handler(param, header, pkt_data + head_len);
    }
    //TLS/SSL协议 端口为443
    if (dst_port == 443 || src_port == 443) {
        g_protocol = "TLS";
        //QString str = TLS_layer_handler(param, header, pkt_data + head_len);
        //v.push_back(str);
    }
    return v;
}

QString Transmission_udp_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    UDP_Header* udp_header = (UDP_Header*)pkt_data;
    //之后可以加上DNS的操作  53端口
    g_protocol = "udp";
    QString src_port = QString::number(ntohs(udp_header->src_port));
    QString dst_port = QString::number(ntohs(udp_header->dst_port));
    QString length = QString::number(ntohs(udp_header->length));
    QString sum = QString("%1").arg(ntohs(udp_header->check_sum), 2, 16, QLatin1Char('0'));
    QString udp_infor;
    //User Datagram Protocol, Src Port: 5353, Dst Port: 5353
    udp_infor = "User Datagram Protocol, Src Port:" + src_port + ", Dst Port: " + dst_port +
        "\n" + "    Source Port:" + src_port + "\n"
        + "    Destination Port:" + dst_port + "\n"
        + "    Check Sum:0x" + sum + "\n";
    //不考虑udp上层的其他协议
    return udp_infor;
}

QString TLS_layer_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    g_protocol = "TLS";
    //从pkt_data开始就是HTTP的相关信息了 直接输出即可
    QString re = "TLSv1 Record Layer: Application Data Protocol: http-over-tls\n";
    re += "    Content Type:0x";
    for (int i = 1;i < 3;i++) {
        re += QString("%1").arg(pkt_data[i - 1], 2, 16, QLatin1Char('0'));
    }
    re += "\n";
    re += "    Version: 0x";
    for (int i = 3;i < 7;i++) {
        re += QString("%1").arg(pkt_data[i - 1], 2, 16, QLatin1Char('0'));
    }
    re += "\n";
    re += "    Length:0x";
    for (int i = 7;i < 11;i++) {
        re += QString("%1").arg(pkt_data[i - 1], 2, 16, QLatin1Char('0'));
    }
    //0x0301 TLS v1   0x0303 TLS v1.2
    return re;
}


class MyThread :public QThread
{
public:
    void run() {
        pcap_loop(sniffer.handler, 0, data_link_handler, NULL);
    }

    ~MyThread() {
        wait();
    }
};


//耗时的操作
void function_needmoretime(MainDialogClass* main_d)
{
    while (true) {
        if (main_d->choice_m != -1) {
            break;
        }
    } 
    char* filter;
    QByteArray ba = main_d->filter_m.toLatin1(); // must
    filter = ba.data();
    sniffer = Network_Packet(filter);
    sniffer.getInterfaces();
    if (sniffer.dev_num == 4)
       sniffer.choose_inter(main_d->choice_m + 2);
    if (sniffer.dev_num == 5)
       sniffer.choose_inter(main_d->choice_m + 1);
    //qDebug() << sniffer.handler;
    pcap_loop(sniffer.handler, 0, data_link_handler, NULL);
}

/*0x0000000180024CC4 (wpcap.dll)处(位于 QtWidgetsApplication1.exe 中)引发的异常: 0xC0000005: 读取位置 0x00000000000002C0 时发生访问冲突。*/

int main(int argc, char* argv[]) {
    //首先用户进入到的是选择网卡的界面
    //网卡选择之后，界面跳转到抓包界面
    QApplication a(argc, argv);
    QtWidgetsApplication1 w;
    model = new QStandardItemModel(&w);
    //界面显示
    QStringList strHeader;
    strHeader << "Time" << "Source" << "DEST" << "Protocol" << "Length" << "0X_Infor" << "More";
    model->setHorizontalHeaderLabels(strHeader);
    w.ui.tableView->setModel(model);
    w.ui.tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    w.ui.tableView->setEditTriggers(QAbstractItemView::NoEditTriggers);//当前的数据不能被编辑
    w.ui.tableView->setColumnWidth(1, 250);
    w.ui.tableView->setColumnWidth(2, 250);
    //w.show();
    sniffer.getInterfaces();
    pcap_if_t* d=sniffer.alldevs;
    MainDialogClass* main_d = new MainDialogClass();
    for (d = sniffer.alldevs;d;d = d->next) {
        main_d->ui.comboBox->addItem(d->name);
    }
    main_d->show();
    w.show();
   /*
    char* filter;
    QByteArray ba = main_d->filter_m.toLatin1(); // must
    filter = ba.data();

    sniffer = Network_Packet(filter); 
    //sniffer.getInterfaces();
    if (sniffer.dev_num == 4)
        sniffer.choose_inter(main_d->choice_m+1);
    if (sniffer.dev_num == 5)
        sniffer.choose_inter(main_d->choice_m + 2);
    */
    QFuture<void> future = QtConcurrent::run(function_needmoretime,main_d);
    while (!future.isFinished())
    {
        QApplication::processEvents();
    }
    //MyThread my_thread = MyThread();
    //my_thread.start();
  
    a.exec();
    return 0;
}
