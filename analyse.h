//
// Created by root on 17-1-19.
//

#ifndef NIC_MONITOR_ANALYSE_H
#define NIC_MONITOR_ANALYSE_H

#define SCREEN_FRAME 0x0001

#define PROTO_ETH 0x0002
#define PROTO_ARP 0x0004
#define PROTO_IP 0x0008
#define PROTO_ICMP 0x0010
#define PROTO_TCP 0x0020
#define PROTO_UDP 0x0040

#define ADDR_MAC 0x0080
#define ADDR_IP 0x0100

#define TYPE_NONE 0
#define TYPE_PORT 1
#define TYPE_MAC 2
#define TYPE_IP 3

struct ip_addr {
    unsigned char addr[4];
    unsigned short port;
};
union addr6 {
    unsigned char mac[6];
    struct ip_addr ip;
};
struct addr {
    int type;
    union addr6 addr;
};

void* analyse(void* v);

#endif //NIC_MONITOR_ANALYSE_H
