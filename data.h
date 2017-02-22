//
// Created by root on 17-1-19.
//

#ifndef NIC_MONITOR_DATA_H
#define NIC_MONITOR_DATA_H

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <string.h>
#include <net/if.h>
#include <semaphore.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <errno.h>

#define BUFFER_MAX 2048
#define LIST_MAX 0

//option flag
#define FLAG_HELP 0x00000001
#define FLAG_BUILD 0x00000002
#define FLAG_IMPORT 0x00000004
#define FLAG_EXPORT 0x00000008
#define FLAG_S_FRAME 0x00000010
#define FLAG_PROTO 0x00000020
#define FLAG_ADDR 0x00000040
#define FLAG_FILE_MAC 0x00000100
#define FLAG_COUNT 0x00000200

//option argument count control
#define NO_ARG 0000
#define OPT_ARG 0001
#define SINGLE_ARG 0010
#define MULTI_ARG 0100

//thread messages
#define THREAD_MSG_FIN 1

//exit codes
#define ERR_OPT_MISS_ARG 0x00000001
#define ERR_OPT_IO_CONFUSE 0x00000002
#define ERR_PERMISSION_DENIED 0x00000004
#define ERR_FILE_INACCESSIBLE 0x00000008

#define ETH_TYPE_ARP 0x0806
#define ETH_TYPE_IP 0x0800
#define ETH_TYPE_REMAIN 0xffff

#define ARP_HARD_TYPE_ETH 0x0001
#define ARP_PROTO_IP 0x0800
#define ARP_OPT_REQ 0x0001
#define ARP_OPT_ACK 0x0002

#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP 6
#define IP_PROTO_UDP 17

#define ICMP_RP 0
#define ICMP_DU 3
#define ICMP_RD 5
#define ICMP_RQ 8

#define UNPACK_D 0
#define UNPACK_N 1
#define UNPACK_T 2

typedef unsigned char u_char;
typedef unsigned int u_int;
typedef u_char* u_string;
typedef char* string;

struct opts{
    long long flag;
    u_int cnt;
    string file;
    string file_mac;
    string* proto;
    string* addr;
};

typedef struct frame{
    time_t time;
    u_int len;
    u_string cont;
}fbundle;
typedef struct frame_que{
    fbundle frame;
    struct frame_que* prev;
    struct frame_que* next;
}frame_que;
struct s_b_list{
    string key;
    string val;
    u_int len;
//    struct s_b_list* prev;
    struct s_b_list* next;
};
struct ui_b_list {
    string key;
    u_int val;
//    struct ui_b_list* prev;
    struct ui_b_list* next;
};
typedef struct bundle {
    int valid;
    time_t time;
    struct s_b_list* str_list;
    struct ui_b_list* ui_list;
}bundle;
typedef struct bd_que{
    bundle bd;
    struct bd_que* prev;
    struct bd_que* next;
}bd_que;
typedef struct statistics {
    time_t start;
    time_t end;

    u_int frame_short;	//√
    u_int frame_long;	//√
    u_int frame_normal;	//√

    u_int mac_broad;	//√
//    u_int mac_short;
//    u_int mac_long;
//    u_int mac_byte;
    u_int bps;
    u_int btps;
    u_int arp_pkt;
    u_int ip_broad;
    u_int ip_byte;      //√
    u_int ip_pkt;       //√
    u_int tcp_pkt;      //√
    u_int udp_pkt;      //√
    u_int icmp_pkt;     //√
    u_int icmp_rd;      //√
    u_int icmp_rp;      //√
    u_int icmp_rq;      //√
    u_int icmp_du;      //√
}stats;
typedef struct mac_list{
    u_string mac;
    struct mac_list* next;
}mac_list;
fbundle init_fbundle();
void destroy_fbundle(fbundle* frame);
frame_que init_fq();
int push_back_fq(frame_que* fque, const fbundle* frame);
fbundle* pop_front_fq(frame_que* fque, fbundle* frame);
void destroy_fq(frame_que* fque);
bundle init_bundle();
int put_string(bundle* bd, const string k, const string v, const u_int len);
int get_string(const bundle* bd, const string k, string v, const u_int len);
int put_u_int(bundle* bd, const string k, const u_int v);
int get_u_int(const bundle* bd, const string k, u_int* v);
void destroy_bd(bundle* bd);
bd_que init_bdq();
int push_back_bdq(bd_que* bdque, const bundle* bd);
bundle* pop_front_bdq(bd_que* bdque, bundle* bd);
void destroy_bdq(bd_que* bdque);
stats init_stats();
mac_list init_list();
int insert_list(mac_list* mlist, u_string mac);
void destroy_list(mac_list* mlist);

//Global vars
struct opts opt;
int sig,err,file;
frame_que fque;
bd_que bdque;
stats table;
u_string ip_mask;
sem_t sem_complete,sem_fin,sem_fq,sem_bdq;
pthread_mutex_t mutex_fq,mutex_bdq;
mac_list mlist;
unsigned long long byte;

#endif //NIC_MONITOR_DATA_H
