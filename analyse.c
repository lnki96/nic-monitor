#include <string.h>
#include "analyse.h"
#include "data.h"

#define PRT_F_WIDTH 20

static int mode;
struct addr *addr_list;
static fbundle frame;
static bundle bd;

int set_analyser(struct opts opt);
void fin_analyser();
bundle* analyse_frame(fbundle* frame, bundle* bd);
bundle* analyse_eth(fbundle* frame, bundle* bd);
bundle* analyse_arp(fbundle* frame, bundle* bd);
bundle* analyse_ip(fbundle* frame, bundle* bd);
bundle* analyse_icmp(fbundle* frame, bundle* bd);
bundle* analyse_tcp(fbundle* frame, bundle* bd);
bundle* analyse_udp(fbundle* frame, bundle* bd);
bundle* analyse_default(fbundle* frame, bundle* bd);

int isexist(const struct addr *addr_list, u_string addr, u_short port, int type);
fbundle* unpack(fbundle* frame, int lvl);
void print_frame(bundle* bd);
void print_eth(bundle* bd);
void print_arp(bundle* bd);
void print_ip(bundle* bd);
void print_icmp(bundle* bd);
void print_tcp(bundle* bd);
void print_udp(bundle* bd);
void print_default(bundle* bd);
long long merge_byte(u_char* src, int n);
void print_ipv4(u_char* ip);
char* to_bin(char* s, long long val, int bit);

void* analyse(void* v) {
    mode = set_analyser(opt);

    frame = init_fbundle();
    pop_front_fq(&fque, &frame);
    bd = init_bundle();
    bd.time=frame.time;
    push_back_bdq(&bdque, &bd);
    while (1) {
        frame = init_fbundle();
        pop_front_fq(&fque, &frame);
        bd = init_bundle();
        if (frame.len) {
            //TODO: Check crc
            analyse_frame(&frame, &bd);
            push_back_bdq(&bdque, &bd);
            if (bd.valid)
                print_frame(&bd);

            destroy_fbundle(&frame);
        } else
            break;
    }
    bd.valid = 0;
    bd.time=frame.time;
    put_u_int(&bd, "msg", THREAD_MSG_FIN);
    push_back_bdq(&bdque, &bd);

    fin_analyser();
    return v;
}

int set_analyser(struct opts opt) {
    int flag = 0, cnt;
    u_int it, mac[6], ip[4], port;
    string *ptr;

    if (opt.flag & FLAG_S_FRAME)
        flag |= SCREEN_FRAME;

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

    ptr = opt.addr;
    for (it = 0; *ptr++; it++);
    addr_list = (struct addr *) calloc(sizeof(struct addr), ++it);
    if (opt.flag & FLAG_ADDR) {
        it = 0;
        ptr = opt.addr;
        while (*ptr) {
            if (sscanf(*ptr, "%2x:%2x:%2x:%2x:%2x:%2x", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6) {
                flag |= ADDR_MAC;
                addr_list[it].type = TYPE_MAC;
                addr_list[it].addr.mac[0] = (u_char) mac[0];
                addr_list[it].addr.mac[1] = (u_char) mac[1];
                addr_list[it].addr.mac[2] = (u_char) mac[2];
                addr_list[it].addr.mac[3] = (u_char) mac[3];
                addr_list[it].addr.mac[4] = (u_char) mac[4];
                addr_list[it].addr.mac[5] = (u_char) mac[5];
            } else {
                flag |= ADDR_IP;
                if (!(cnt = sscanf(*ptr, "%u.%u.%u.%u:%u", &ip[0], &ip[1], &ip[2], &ip[3], &port))) {
                    addr_list[it].type = TYPE_PORT;
                    sscanf(*ptr, ":%u", &port);
                    memset(ip, 0, 4 * sizeof(int));
                } else {
                    addr_list[it].type = TYPE_IP;
                    if (cnt == 4)
                        port = 0;
                }
                addr_list[it].addr.ip.addr[0] = (u_char) ip[0];
                addr_list[it].addr.ip.addr[1] = (u_char) ip[1];
                addr_list[it].addr.ip.addr[2] = (u_char) ip[2];
                addr_list[it].addr.ip.addr[3] = (u_char) ip[3];
                addr_list[it].addr.ip.port = (short) port;
            }

            it++;
            ptr++;
        }
    }
//    if (opt.flag & FLAG_PORT) {
//        flag |= PORT;
////        if (!(flag & (PROTO_TCP | PROTO_UDP)))
////            flag |= PROTO_ETH | PROTO_IP | PROTO_TCP | PROTO_UDP;
//        ptr = opt.port;
//        while (*ptr) {
//            sscanf(*ptr, "%u", &port);
//            addr_list[it].addr.ip.addr[0] = TYPE_IP;
//            memset(&addr_list[it].addr, 0, 4);
//            addr_list[it].addr.ip.port =(short) port;
//
//            it++;
//            ptr++;
//        }
//    }
    addr_list[it].type = TYPE_NONE;

    return flag;
}

void fin_analyser(){
    sem_post(&sem_complete);
}

bundle* analyse_frame(fbundle* frame, bundle* bd) {
    u_string cont = frame->cont;
    put_u_int(bd, "flen", frame->len);
    string x = calloc(sizeof(char), 16);
    free(x);
    put_string(bd, "frame", frame->cont, frame->len);

    bd = (mode & PROTO_ETH) ? analyse_eth(frame, bd) : analyse_default(frame, bd);

    frame->cont = cont;
    return bd;
}

bundle* analyse_eth(fbundle* frame, bundle* bd){
    u_int type;
    bundle* (*jump)(fbundle*,bundle*);

    if (!(mode & (ADDR_MAC)) ||
        (isexist(addr_list, frame->cont, 0, TYPE_MAC) || isexist(addr_list, frame->cont + 6, 0, TYPE_MAC))) {
        put_string(bd, "d_mac_d", frame->cont, 6);
        put_string(bd, "d_mac_s", frame->cont + 6, 6);
        type = merge_byte(frame->cont + 2 * 6, 2);
        switch (type) {
            case ETH_TYPE_ARP:
                if (mode & PROTO_ARP) {
                    jump = analyse_arp;
                    put_u_int(bd, "d_type", type);
                } else
                    jump = analyse_default;
                break;
            case ETH_TYPE_IP:
                if (mode & PROTO_IP) {
                    jump = analyse_ip;
                    put_u_int(bd, "d_type", type);
                } else
                    jump = analyse_default;
                break;
            default:
                jump = analyse_default;
                break;
        }

        unpack(frame, UNPACK_D);
    }
    else
        jump=analyse_default;

    return jump(frame,bd);
}

bundle* analyse_arp(fbundle* frame, bundle* bd) {
    if ((!(mode & (ADDR_MAC)) ||
         (isexist(addr_list, frame->cont + 8, 0, TYPE_MAC) || isexist(addr_list, frame->cont + 18, 0, TYPE_MAC)))
        && (!(mode & (ADDR_IP)) ||
            (isexist(addr_list, frame->cont + 14, 0, TYPE_IP) || isexist(addr_list, frame->cont + 24, 0, TYPE_IP)))) {
        put_u_int(bd, "ud_type", merge_byte(frame->cont, 2));
        put_u_int(bd, "ud_proto", merge_byte(frame->cont + 2, 2));
        put_u_int(bd, "ud_len", merge_byte(frame->cont + 4, 1));
        put_u_int(bd, "ud_addr_len", merge_byte(frame->cont + 5, 1));
        put_u_int(bd, "ud_opt", merge_byte(frame->cont + 6, 2));
        put_string(bd, "ud_mac_s", frame->cont + 8, 6);
        put_string(bd, "ud_ip_s", frame->cont + 14, 4);
        put_string(bd, "ud_mac_d", frame->cont + 18, 6);
        put_string(bd, "ud_ip_d", frame->cont + 24, 4);

        return bd;
    } else
        return analyse_default(frame, bd);
}

bundle* analyse_ip(fbundle* frame, bundle* bd) {
    u_int proto;
    bundle *(*jump)(fbundle *, bundle *);

    if (!(mode & (ADDR_IP)) ||
        (isexist(addr_list, frame->cont + 12, 0, TYPE_IP) || isexist(addr_list, frame->cont + 16, 0, TYPE_IP))) {
        put_u_int(bd, "n_ver", *(frame->cont) / 0x10);
        put_u_int(bd, "n_hlen", *(frame->cont) % 0x10);
        put_u_int(bd, "n_type", merge_byte(frame->cont + 1, 1));
        put_u_int(bd, "n_len", merge_byte(frame->cont + 2, 2));
        put_u_int(bd, "n_id", merge_byte(frame->cont + 4, 2));
        put_u_int(bd, "n_flag", merge_byte(frame->cont + 6, 1) / 0x20);
        put_u_int(bd, "n_off", merge_byte(frame->cont + 6, 2) % 0x2000);
        put_u_int(bd, "n_ttl", merge_byte(frame->cont + 8, 1));
        proto = merge_byte(frame->cont + 9, 1);
        switch (proto) {
            case IP_PROTO_ICMP:
                if (mode & PROTO_ICMP) {
                    jump = analyse_icmp;
                    put_u_int(bd, "n_proto", proto);
                } else
                    jump = analyse_default;
                break;
            case IP_PROTO_TCP:
                if (mode & PROTO_TCP) {
                    jump = analyse_tcp;
                    put_u_int(bd, "n_proto", proto);
                } else
                    jump = analyse_default;
                break;
            case IP_PROTO_UDP:
                if (mode & PROTO_UDP) {
                    jump = analyse_udp;
                    put_u_int(bd, "n_proto", proto);
                } else
                    jump = analyse_default;
                break;
            default:
                jump = analyse_default;
                break;
        }
        put_u_int(bd, "n_crc", merge_byte(frame->cont + 10, 2));
        put_string(bd, "n_ip_s", frame->cont + 12, 4);
        put_string(bd, "n_ip_d", frame->cont + 16, 4);

        unpack(frame, UNPACK_N);
    } else
        jump = analyse_default;

    return jump(frame, bd);
}

bundle* analyse_icmp(fbundle* frame, bundle* bd){
    put_u_int(bd,"t_type",merge_byte(frame->cont,1));
    put_u_int(bd,"t_code",merge_byte(frame->cont+1,1));
    put_u_int(bd,"t_crc",merge_byte(frame->cont+2,2));
    put_u_int(bd,"t_id",merge_byte(frame->cont+4,2));
    put_u_int(bd,"t_seq",merge_byte(frame->cont+6,2));

    return bd;
}

bundle* analyse_tcp(fbundle* frame, bundle* bd) {
    char ip_s[4], ip_d[4];
    if (!(get_string(bd, "n_ip_s", ip_s, 4) || get_string(bd, "n_ip_d", ip_d, 4)))
        if (!(mode & ADDR_IP) || (isexist(addr_list, ip_s, merge_byte(frame->cont, 2), TYPE_IP) ||
                                  isexist(addr_list, ip_d, merge_byte(frame->cont + 2, 2), TYPE_IP))) {
            put_u_int(bd, "t_port_s", merge_byte(frame->cont, 2));
            put_u_int(bd, "t_port_d", merge_byte(frame->cont + 2, 2));
            put_u_int(bd, "t_seq", merge_byte(frame->cont + 4, 4));
            put_u_int(bd, "t_ack", merge_byte(frame->cont + 8, 4));
            put_u_int(bd, "t_off", *(frame->cont + 12) / 0x10);
            put_u_int(bd, "t_remain", merge_byte(frame->cont + 12, 1) % 0x1000 / 0x40);
            put_u_int(bd, "t_flag", *(frame->cont + 13) % 0x40);
            put_u_int(bd, "t_win", merge_byte(frame->cont + 14, 2));
            put_u_int(bd, "t_crc", merge_byte(frame->cont + 16, 2));
            put_u_int(bd, "t_ptr", merge_byte(frame->cont + 18, 2));
        } else
            bd = analyse_default(frame, bd);

    return bd;
}

bundle* analyse_udp(fbundle* frame, bundle* bd) {
    char ip_s[4], ip_d[4];
    if (!(get_string(bd, "n_ip_s", ip_s, 4) || get_string(bd, "n_ip_d", ip_d, 4)))
        if (!(mode & ADDR_IP) || (isexist(addr_list, ip_s, merge_byte(frame->cont, 2), TYPE_IP) ||
                                  isexist(addr_list, ip_d, merge_byte(frame->cont + 2, 2), TYPE_IP))) {
            put_u_int(bd, "t_port_s", merge_byte(frame->cont, 2));
            put_u_int(bd, "t_port_d", merge_byte(frame->cont + 2, 2));
            put_u_int(bd, "t_len", merge_byte(frame->cont + 4, 2));
            put_u_int(bd, "t_crc", merge_byte(frame->cont + 6, 2));
        } else
            bd = analyse_default(frame, bd);

    return bd;
}

bundle* analyse_default(fbundle* frame, bundle* bd){
    bd->valid=0;

    return bd;
}

int isexist(const struct addr *addr_list, u_string addr, u_short port, int type) {
    switch (type) {
        case TYPE_MAC:
            while (addr_list->type != TYPE_NONE) {
                if (addr && addr_list->type == type && !memcmp(addr_list->addr.mac, addr, 6))
                    return 1;
                addr_list++;
            }
            break;
        case TYPE_IP:
            while (addr_list->type != TYPE_NONE) {
                if ((((addr && addr_list->type == type && !memcmp(addr_list->addr.ip.addr, addr, 6)) ||
                      addr_list->type == TYPE_PORT) &&
                     (!addr_list->addr.ip.port || !port || addr_list->addr.ip.port == port)))
                    return 1;
                addr_list++;
            }
            break;
        default:
            break;
    }

//    while (*addr_list) {
//        switch (type) {
//            case TYPE_MAC:
//                if (!memcmp(addr_list->addr.mac, addr, 6))
//                    return 1;
//                addr_list++;
//                break;
//            case TYPE_IP:
//                break;
//            default:
//                break;
//        }
//        if (addr_list->type == type && addr && !memcmp(*addr_list + 1, addr, type))
//            return 1;
//        addr_list++;
//    }

    return 0;
}

//int isexist_port(const int* port_list, int port) {
//    while (*port_list != -1) {
//        if (*port_list == port)
//            return 1;
//        port_list++;
//    }
//
//    return 0;
//}

fbundle* unpack(fbundle* frame, int lvl){
    switch(lvl){
        case UNPACK_D:
            frame->cont+=14;
            frame->len-=18;
            break;
        case UNPACK_N:
            frame->cont+=4*(*(frame->cont)%0x10);
            frame->len-=4*(*(frame->cont)%0x10);
            break;
        case UNPACK_T:

            break;
        default:
            break;
    }
    return frame;
}

void print_frame(bundle* bd) {
    printf("\n********************************************************************************\n\n");

    if (mode & SCREEN_FRAME) {
        int i;
        u_int flen;
        get_u_int(bd, "flen",&flen);
        u_char cont[flen];
        u_string ptr = cont;
        get_string(bd, "frame", cont, flen);
        for (i = 1; i <= flen; i++) {
            printf("%02x ", *ptr++);
            if (!(i % PRT_F_WIDTH))
                printf("\n");
        }
        if (i % PRT_F_WIDTH)
            printf("\n");
    }
    if (mode & (PROTO_ETH | PROTO_ARP | PROTO_IP | PROTO_ICMP | PROTO_TCP | PROTO_UDP))
        print_eth(bd);
}

void print_eth(bundle* bd){
    u_int type;
    u_char mac_s[6], mac_d[6];
    void (*jump)(bundle*);

    printf("Protocol: Ethernet\n");
    printf("+%s+%s+%s+\n","------------------------","------------------------","--------");
    get_string(bd,"d_mac_d",mac_d,6);
    get_string(bd,"d_mac_s",mac_s,6);
    get_u_int(bd,"d_type",&type);
    printf("|   ");
    print_mac(mac_d);
    printf("    |   ");
    print_mac(mac_s);
    printf("    |");
    switch(type){
        case ETH_TYPE_ARP:
            printf("  ARP   |\n");
            jump=print_arp;
            break;
        case ETH_TYPE_IP:
            printf("   IP   |\n");
            jump=print_ip;
            break;
        default:
            printf("unknown |\n");
            jump=print_default;
            break;
    }
    printf("+%s+%s+%s+\n","------------------------","------------------------","--------");

    jump(bd);
}

void print_arp(bundle* bd){
    u_int type,proto,option;
    u_char len,addr_len;
    u_char mac_s[6], mac_d[6], ip_s[4], ip_d[4];

    printf("Protocol: ARP\n");
    printf("+%s+%s+\n","-----------------","-----------------");
    get_u_int(bd,"ud_type",&type);
    get_u_int(bd,"ud_proto",&proto);
    switch(type){
        case ARP_HARD_TYPE_ETH:
            printf("|  %d (Ethernet)   |",type);
            break;
        default:
            printf("|   %d (unknown)   |",type);
            break;
    }
    switch(proto){
        case ARP_PROTO_IP:
            printf("    %04x (IP)    |\n",proto);
            break;
        default:
            printf("  %04x (unknown) |\n",proto);
            break;
    }
    printf("+%s+%s+%s+\n","--------","--------","-----------------");
    get_u_int(bd,"ud_len",&len);
    get_u_int(bd,"ud_addr_len",&addr_len);
    get_u_int(bd,"ud_opt",&option);
    printf("|  %3u   |  %3u   |",len,addr_len);
    switch(option){
        case ARP_OPT_REQ:
            printf(" %u (ARP require) |\n",option);
            break;
        case ARP_OPT_ACK:
            printf("   %u (ARP ACK)   |\n",option);
            break;
        default:
            printf("   %u (unknown)   |\n",option);
            break;
    }
    printf("+%s+%s+%s+%s+\n","--------","--------","-----------------","-----------------");
    get_string(bd,"ud_mac_s",mac_s,6);
    printf("|                  ");
    print_mac(mac_s);
    printf("                  |\n");
    printf("+%s+%s+\n","-----------------------------------","-----------------");
    get_string(bd,"ud_ip_s",ip_s,4);
    printf("|          ");
    print_ipv4(ip_s);
    printf("          |\n");
    printf("+%s+%s+\n","-----------------------------------","-----------------");
    get_string(bd,"ud_mac_d",mac_d,6);
    printf("|                  ");
    print_mac(mac_d);
    printf("                  |\n");
    printf("+%s+%s+\n","-----------------------------------","-----------------");
    get_string(bd,"ud_ip_d",ip_d,4);
    printf("|          ");
    print_ipv4(ip_d);
    printf("          |\n");
    printf("+%s+\n","-----------------------------------");
}

void print_ip(bundle* bd){
    u_int ver=0,hlen=0,type,flag=0,ttl,proto,len,id,off,crc;
    u_char ip_s[4], ip_d[4];
    char bin[9];
    void (*jump)(bundle*);

    printf("Protocol: IP\n");
    printf("+%s+%s+%s+%s+\n","-------","-------","--------------","----------------------------");
    get_u_int(bd,"n_ver",&ver);
    get_u_int(bd,"n_hlen",&hlen);
    get_u_int(bd,"n_type",&type);
    get_u_int(bd,"n_len",&len);
    printf("|  %2u   |  %3u  |   %s   |           %5u            |\n",ver,hlen*4,to_bin(bin,type,8),len);
    printf("+%s+%s+%s+%s+%s+\n","-------","-------","--------------","------","---------------------");
    get_u_int(bd,"n_id",&id);
    get_u_int(bd,"n_flag",&flag);
    get_u_int(bd,"n_off",&off);
    printf("|            %5u             | %s  |          %u          |\n",id,to_bin(bin,flag,3),off);
    printf("+%s+%s+%s+%s+\n","---------------","--------------","------","---------------------");
    get_u_int(bd,"n_ttl",&ttl);
    get_u_int(bd,"n_proto",&proto);
    get_u_int(bd,"n_crc",&crc);
    printf("|      %3u      |",ttl);
    switch(proto){
        case IP_PROTO_ICMP:
            printf("   %d (ICMP)   |",proto);
            jump=print_icmp;
            break;
        case IP_PROTO_TCP:
            printf("   %d (TCP)    |",proto);
            jump=print_tcp;
            break;
        case IP_PROTO_UDP:
            printf("   %d (UDP)   |",proto);
            jump=print_udp;
            break;
        default:
            printf(" %d (unknown)  |",proto);
            jump=print_default;
            break;
    }
    printf("           %5d            |\n",crc);
    printf("+%s+%s+%s+\n","---------------","--------------","----------------------------");
    get_string(bd,"n_ip_s",ip_s,4);
    printf("|                      ");
    print_ipv4(ip_s);
    printf("                      |\n");
    printf("+%s+\n","-----------------------------------------------------------");
    get_string(bd,"n_ip_d",ip_d,4);
    printf("|                      ");
    print_ipv4(ip_d);
    printf("                      |\n");
    printf("+%s+\n","-----------------------------------------------------------");

    jump(bd);
}

void print_icmp(bundle* bd){
    u_int type,code,crc,id,seq;

    printf("Protocol: ICMP\n");
    printf("+%s+%s+%s+\n","--------","--------","----------------");
    get_u_int(bd,"t_type",&type);
    get_u_int(bd,"t_code",&code);
    get_u_int(bd,"t_crc",&crc);
    printf("|  %3u   |  %3u   |     %5u      |\n",type,code,crc);
    printf("+%s+%s+%s+\n","--------","--------","----------------");
    get_u_int(bd,"t_id",&id);
    get_u_int(bd,"t_seq",&seq);
    printf("|      %5u      |     %5u      |\n",id,seq);
    printf("+%s+%s+\n","-----------------","----------------");
}

void print_tcp(bundle* bd){
    u_int off=0,remain=0,flag=0,port_s,port_d,seq,ack,win,crc,urg_ptr;
    char bin[9];

    printf("Protocol: TCP\n");
    printf("+%s+%s+\n","----------------------------","----------------------------");
    get_u_int(bd,"t_port_s",&port_s);
    get_u_int(bd,"t_port_d",&port_d);
    printf("|           %5u            |           %5u            |\n",port_s,port_d);
    printf("+%s+%s+\n","----------------------------","----------------------------");
    get_u_int(bd,"t_seq",&seq);
    printf("|                       %10u                        |\n",seq);
    printf("+%s+\n","---------------------------------------------------------");
    get_u_int(bd,"t_ack",&ack);
    printf("|                       %10u                        |\n",ack);
    printf("+%s+%s+%s+%s+\n","-----","-----------","----------","----------------------------");
    get_u_int(bd,"t_off",&off);
    get_u_int(bd,"t_remain",&remain);
    get_u_int(bd,"t_flag",&flag);
    get_u_int(bd,"t_win",&win);
    printf("| %2u  |    %3u    |  %s  |           %5u            |\n",off,remain,to_bin(bin,flag,6),win);
    printf("+%s+%s+%s+%s+\n","-----","-----------","----------","----------------------------");
    get_u_int(bd,"t_crc",&crc);
    get_u_int(bd,"t_ptr",&urg_ptr);
    printf("|           %5u            |         0x%08x         |\n",crc,urg_ptr);
    printf("+%s+%s+\n","----------------------------","----------------------------");
}

void print_udp(bundle* bd){
    u_int port_s,port_d,len,crc;

    printf("Protocol: UDP\n");
    printf("+%s+%s+\n","----------------------------","----------------------------");
    get_u_int(bd,"t_port_s",&port_s);
    get_u_int(bd,"t_port_d",&port_d);
    printf("|            %5u           |            %5u           |\n",port_s,port_d);
    printf("+%s+%s+\n","----------------------------","----------------------------");
    get_u_int(bd,"t_len",&len);
    get_u_int(bd,"t_crc",&crc);
    printf("|            %5u           |            %5u           |\n",len,crc);
    printf("+%s+%s+\n","----------------------------","----------------------------");
}

void print_default(bundle* bd){

}

long long merge_byte(u_char* src, int n){
    long long res=0;
    if(n<=sizeof(long long)){
        for(int i=0;i<n;i++){
            res=(res<<8)+*src++;
        }
    }
    return res;
}

void print_mac(u_char* mac){
    printf("%02x:%02x:%02x:%02x:%02x:%02x",*mac,*(mac+1),*(mac+2),*(mac+3),*(mac+4),*(mac+5));
}

void print_ipv4(u_char* ip){
    printf("%3d.%3d.%3d.%3d",*ip,*(ip+1),*(ip+2),*(ip+3));
}

char* to_bin(char* s, long long val, int bit){
    s+=bit;
    for(int i=0;i<bit;i++){
        *--s=(val%2)?'1':'0';
        val>>=1;
    }
    s[bit]='\0';
    return s;
}