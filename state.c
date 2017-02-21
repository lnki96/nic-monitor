#include "data.h"
#include "state.h"

#define FLEN_MIN 64
#define FLEN_MAX 1518

static int mode;
static u_int flen, msg;
static bundle bd;

int set_stater(struct opts opt);
void fin_stater();
void state_eth(stats* table, const bundle* bd);
void state_arp(stats* table, const bundle* bd);
void state_ip(stats* table, const bundle* bd);
void state_icmp(stats* table, const bundle* bd);
void state_tcp(stats* table, const bundle* bd);
void state_udp(stats* table, const bundle* bd);
void query_mac(const bundle* bd);

void* state(void* v) {
    mode = set_stater(opt);

    bd = init_bundle();
    pop_front_bdq(&bdque, &bd);
    table.start=bd.time;
    while (1) {
        get_u_int(&bd, "flen", &flen);
        byte += flen;
        if (bd.valid) {
            //TODO: get ip mask
            query_mac(&bd);
            if (flen < FLEN_MIN) {
                table.frame_short++;
            } else if (flen > FLEN_MAX) {
                table.frame_long++;
            } else {
                table.frame_normal++;
            }
            state_eth(&table, &bd);
        } else if (!get_u_int(&bd, "msg", &msg) && msg == THREAD_MSG_FIN)
            break;

        bd = init_bundle();
        pop_front_bdq(&bdque, &bd);
    }
    table.end = bd.time;
    table.btps = (u_int) (byte / difftime(table.end, table.start));
    table.bps = table.btps * 8;

    fin_stater();
    return v;
}

int set_stater(struct opts opt){
    int flag=0;
    string* ptr;

    if (opt.flag & FLAG_PROTO) {
        ptr = opt.proto;
        while (*ptr) {
            if (!strcmp(*ptr, "eth") || !strcmp(*ptr, "ethernet"))
                flag |= PROTO_ETH;
            else if (!strcmp(*ptr, "arp"))
                flag |= PROTO_ETH | PROTO_ARP;
            else if (!strcmp(*ptr, "ip"))
                flag |= PROTO_ETH | PROTO_IP;
            else if (!strcmp(*ptr, "icmp"))
                flag |= PROTO_ETH | PROTO_IP | PROTO_ICMP;
            else if (!strcmp(*ptr, "tcp"))
                flag |= PROTO_ETH | PROTO_IP | PROTO_TCP;
            else if (!strcmp(*ptr, "udp"))
                flag |= PROTO_ETH | PROTO_IP | PROTO_UDP;
            ptr++;
        }
        if (!(flag & (PROTO_ARP | PROTO_IP | PROTO_ICMP | PROTO_TCP | PROTO_UDP)))
            flag |= PROTO_ARP | PROTO_IP | PROTO_ICMP | PROTO_TCP | PROTO_UDP;
        else if (!(flag & (PROTO_ICMP | PROTO_TCP | PROTO_UDP)))
            flag |= PROTO_ICMP | PROTO_TCP | PROTO_UDP;
    } else
        flag |= PROTO_ETH | PROTO_ARP | PROTO_IP | PROTO_ICMP | PROTO_TCP | PROTO_UDP;

    return flag;
}

void fin_stater() {
    sem_post(&sem_complete);
}

void state_eth(stats* table,const bundle* bd){
    u_string mac=(char*)calloc(sizeof(char),7);
    u_int type;
    char mac_brd[7]={0xff,0xff,0xff,0xff,0xff,0xff,'\0'};

    get_string(bd,"d_mac_d",mac,6);
    if(!memcmp(mac,mac_brd,6)){
        table->mac_broad++;
    }

    get_u_int(bd,"d_type",&type);
    switch(type){
        case ETH_TYPE_ARP:
            state_arp(table,bd);
            break;
        case ETH_TYPE_IP:
            state_ip(table,bd);
            break;
        default:
            break;
    }
}

void state_arp(stats* table, const bundle* bd){

    table->arp_pkt++;
}

void state_ip(stats* table, const bundle* bd){
    u_string ip=(char*)calloc(sizeof(char),5);
    u_int ui;
    u_char ip_brd[5]={0xff,0xff,0xff,0xff,'\0'};

    get_string(bd,"n_ip_d",ip,4);
    if(!strcmp(ip,ip_brd)){
        table->ip_broad++;
    }
    table->ip_pkt++;
    get_u_int(bd,"n_len",&ui);
    table->ip_byte+=ui;

    get_u_int(bd,"n_proto",&ui);
    switch (ui){
        case IP_PROTO_ICMP:
            state_icmp(table,bd);
            break;
        case IP_PROTO_TCP:
            state_tcp(table,bd);
            break;
        case IP_PROTO_UDP:
            state_udp(table,bd);
            break;
        default:
            break;
    }
}

void state_icmp(stats* table, const bundle* bd){
    u_int type;
    get_u_int(bd,"t_type",&type);
    switch (type){
        case ICMP_RP:
            table->icmp_rp++;
            break;
        case ICMP_DU:
            table->icmp_du++;
            break;
        case ICMP_RD:
            table->icmp_rd++;
            break;
        case ICMP_RQ:
            table->icmp_rq++;
            break;
        default:
            break;
    }
    table->icmp_pkt++;
}

void state_tcp(stats* table, const bundle* bd){
    table->tcp_pkt++;
}

void state_udp(stats* table, const bundle* bd){
    table->udp_pkt++;
}

//void query_mac(MYSQL* mysql, const bundle* bd)
void query_mac(const bundle* bd) {
    char mac[7];
    get_string(bd, "d_mac_d", mac, 6);
    insert_list(&mlist, mac);
    get_string(bd, "d_mac_s", mac, 6);
    insert_list(&mlist, mac);
}