//
// Created by root on 17-1-19.
//

#ifndef NIC_MONITOR_STATE_H
#define NIC_MONITOR_STATE_H

#define PROTO_ETH 0x0001
#define PROTO_ARP 0x0002
#define PROTO_IP 0x0004
#define PROTO_ICMP 0x008
#define PROTO_TCP 0x0010
#define PROTO_UDP 0x0020

#define COUNT 0x0040

void* state(void* v);

#endif //NIC_MONITOR_STATE_H
