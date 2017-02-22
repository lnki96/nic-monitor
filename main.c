#include <getopt.h>
#include <fcntl.h>
#include <time.h>
#include "grab.h"
#include "data.h"
#include "analyse.h"
#include "state.h"

int set_opt(const int argc, char* argv[], struct opts* opt);
int fill_argstr(char** optargs,char* argv[],int flag);
int check_addr(const string* addr);
int check_port(const string* port);
void help();
void sig_handler(int sig);

int main(int argc, char* argv[]) {
    err = 0;
    if ((err = set_opt(argc, argv, &opt))) {
        switch (err) {
            case ERR_OPT_MISS_ARG:
                printf("Invalid operation.\n");
                break;
            default:
                break;
        }
        exit(err);
    } else if (opt.flag & FLAG_HELP) {
        help();
        exit(0);
    }

    pthread_t grabber, analyser, stater;

    fque = init_fq();
    bdque = init_bdq();
    table = init_stats();
    mlist = init_list();

    sem_init(&sem_fq, PTHREAD_PROCESS_PRIVATE, 0);
    sem_init(&sem_bdq, PTHREAD_PROCESS_PRIVATE, 0);
    sem_init(&sem_fin, PTHREAD_PROCESS_PRIVATE, 0);
    sem_init(&sem_complete, PTHREAD_PROCESS_PRIVATE, 0);
    pthread_mutex_init(&mutex_fq, NULL);
    pthread_mutex_init(&mutex_bdq, NULL);

    file = 0;
    if (opt.flag & FLAG_IMPORT) {
        if ((file = open(opt.file, O_RDONLY) < 0))
            exit(ERR_FILE_INACCESSIBLE);
    } else if (opt.flag & FLAG_EXPORT)
        if ((file = open(opt.file, O_WRONLY | O_CREAT) < 0)) {
            exit(ERR_FILE_INACCESSIBLE);
        }

    if (pthread_create(&grabber, NULL, grab, NULL) != 0) {
        printf("Create grabber failed.\n");
        exit(1);
    }
    if (pthread_create(&analyser, NULL, analyse, NULL) != 0) {
        printf("Create analyser failed.\n");
        exit(1);
    }
    if (pthread_create(&stater, NULL, state, NULL) != 0) {
        printf("Create stater failed.\n");
        exit(1);
    }

    signal(SIGINT, sig_handler);

    sem_wait(&sem_fin);

    destroy_fq(&fque);
    destroy_bdq(&bdque);
    destroy_list(&mlist);

    return err;
}

int set_opt(int argc,char* argv[],struct opts* opt) {
    const char *c = NULL,*s;
    string *arg_ptr = NULL;
    char str[BUFFER_MAX];
    int err = 0, method;

    opt->flag = 0;
    opt->file = NULL;
    opt->proto = (char **) calloc(sizeof(char *), argc);
    opt->addr = (char **) calloc(sizeof(char *), argc);

    while (*++argv) {
        method = 0;
        if (**argv == '-') {
            c = *argv + 1;
            if (*c == '-') {
                s=++c;
                c=NULL;
                if (!strcmp(s, "import"))
                    goto import;
                else if (!strcmp(s, "export"))
                    goto export;
                else if (!strcmp(s, "show-frame"))
                    goto show_frame;
                else if (!strcmp(s, "addr-port"))
                    goto address;
                else if (!strcmp(s, "protocol"))
                    goto protocol;
                else if (!strcmp(s, "build"))
                    goto build;
                else if (!strcmp(s, "mac-list"))
                    goto mac_list;
                else if (!strcmp(s, "count"))
                    goto count;
                else if (!strcmp(s, "help"))
                    goto help;
            } else {
                while (c && *c) {
                    switch (*c) {
                        case 'i':
                        import:
                            opt->flag |= FLAG_IMPORT;
                            arg_ptr = &opt->file;
                            method = SINGLE_ARG;
                            break;
                        case 'e':
                        export:
                            opt->flag |= FLAG_IMPORT;
                            arg_ptr = &opt->file;
                            method = SINGLE_ARG;
                            break;
                        case 's':
                        show_frame:
                            opt->flag |= FLAG_S_FRAME;
                            arg_ptr = NULL;
                            method = NO_ARG;
                            break;
                        case 'a':
                        address:
                            opt->flag |= FLAG_ADDR;
                            arg_ptr = opt->addr;
                            method = MULTI_ARG;
                            break;
                        case 'p':
                        protocol:
                            opt->flag |= FLAG_PROTO;
                            arg_ptr = opt->proto;
                            method = MULTI_ARG;
                            break;
                        case 'b':
                        build:
                            opt->flag |= FLAG_BUILD;


                            break;
                        case 'm':
                        mac_list:
                            opt->flag |= FLAG_FILE_MAC;
                            arg_ptr = &opt->file_mac;
                            method = SINGLE_ARG;
                            break;
                        case 'c':
                        count:
                            opt->flag |= FLAG_COUNT;
                            if (sscanf(*(argv + 1), "%u%s", &opt->cnt, str) != 1)
                                err |= ERR_OPT_MISS_ARG;
                            arg_ptr = NULL;
                            method = NO_ARG;
                            break;
                        case 'h':
                        help:
                            opt->flag |= FLAG_HELP;
                            arg_ptr = NULL;
                            method = NO_ARG;
                            break;
                        default:
                            break;
                    }
                    if (c)
                        c++;

                    if ((fill_argstr(arg_ptr, argv, method) && (method != NO_ARG && strlen(c) != 1)) ||
                        (opt->flag & FLAG_ADDR && !check_addr(opt->addr)))
                        err |= ERR_OPT_MISS_ARG;

                    if (err)
                        break;
                }
            }
        }

        if (err)
            break;
    }

    if (opt->flag & FLAG_IMPORT && opt->flag & FLAG_EXPORT)
        err |= ERR_OPT_IO_CONFUSE;

    return err;
}//TODO: complete options: 1. set mac list file  2. done  3. done  4. build & send packets  5. do not wait for another frame when interrupt
//TODO:                   6. import filter list (protocol | address)  7. filter direction  8. set stater  9. flip filter
//TODO:                   10. record receiving time  11. done  12. set capture count  13. mute screen  14. check file existence
//TODO:                   15. set count of packets to grab  16. pause & resume  17. optimize memory management  18. filter statistics
//TODO:                   19. optimize format of args for addr-port filter option  20. domain name support  21. design a inter-thread info pool  .etc

int fill_argstr(char** optargs,char* argv[],int flag) {
    int cnt=0,err=0;

    argv++;
    switch (flag & ~OPT_ARG) {
        case NO_ARG:
            if(*argv && **argv != '-')
                err=-1;
            break;
        case SINGLE_ARG:
            if ((*argv && **argv != '-') && !(*(argv + 1) && **(argv + 1) != '-'))
                *optargs = *argv;
            else if (!(flag & OPT_ARG))
                err=-1;
            break;
        case MULTI_ARG:
            while (*argv && **argv != '-') {
                *optargs = *argv++;
                optargs++;
                cnt++;
            }
            *optargs=NULL;
            if(!(flag&OPT_ARG)&&!cnt)
                err=-1;
            break;
        default:
            break;
    }

    return err;
}

int check_addr(const string* addr){
    string ptr, str = calloc(sizeof(char), BUFFER_MAX);
    int cnt, tmp = 0, buf[4] = {0, 0, 0, 0};
    while (*addr) {
        ptr = *addr++;
        if (sscanf(ptr, "%2x:%2x:%2x:%2x:%2x:%2x%s", &tmp, &tmp, &tmp, &tmp, &tmp, &tmp, str) != 6) {
            *str = '\0';
            if ((cnt = sscanf(ptr, "%u.%u.%u.%u%s", &buf[0], &buf[1], &buf[2], &buf[3], str)) == 4 ||
                (sscanf((!cnt) ? ptr : str, ":%u%s", &tmp, str) == 1 && tmp < 0x10000) &&
                (buf[0] | buf[1] | buf[2] | buf[3]) < 0x100)
                return 1;
        }
        *str = '\0';
    }
    free(str);

    return 0;
}

//int check_port(const string* port){
//    string ptr,str=calloc(sizeof(char),BUFFER_MAX);
//    int tmp;
//    while(*port) {
//        ptr = *port++;
//        tmp = 0x10000;
//        if (sscanf(ptr, "%u%s", &tmp, str) == 1 && tmp < 0x10000)
//            return 1;
//    }
//    free(str);
//
//    return 0;
//}

void help() {
    printf("usage: nic-monitor [-i import_file] [-o export_file] [-m mac_list_file] [-a [[ip_address:port] | mac]]"
                   "              [-p protocols] [-c packet_count] [-s]\n");
}//TODO: complete manual

void sig_handler(int sys_sig) {
    sig = sys_sig;
    switch (sys_sig) {
        case SIGINT:
            printf("\b\b  \b\b");
            for (int i = 0; i < 3; i++)
                sem_wait(&sem_complete);
            mac_list *ptr = &mlist;
            printf("\n********************************************************************************\n\n");
            printf("MAC list\n");
            printf("+-----------------+\n|");
            if(mlist.mac) {
                while (1) {
                    printf("%02x:%02x:%02x:%02x:%02x:%02x",*ptr->mac,*(ptr->mac+1),*(ptr->mac+2),*(ptr->mac+3),*(ptr->mac+4),*(ptr->mac+5));
                    if(!(ptr = ptr->next))
                        break;
                    printf("|\n+-----------------+\n|");
                }
            } else
                printf("NONE             ");
            printf("|\n+-----------------+\n");
            char tm_buf[20];
            printf("Summary\n");
            printf("+-----------------+-------------------+\n");
            strftime(tm_buf,20,"%F %X",localtime(&table.start));
            printf("|%s       |%s|\n", "Start time", tm_buf);
            printf("+-----------------+-------------------+\n");
            strftime(tm_buf,20,"%F %X",localtime(&table.end));
            printf("|%s         |%s|\n", "End time", tm_buf);
            printf("+-----------------+-------------------+\n");
            printf("|%s      |%19d|\n", "Frame short", table.frame_short);
            printf("+-----------------+-------------------+\n");
            printf("|%s     |%19d|\n", "Frame normal", table.frame_normal);
            printf("+-----------------+-------------------+\n");
            printf("|%s       |%19d|\n", "Frame long", table.frame_long);
            printf("+-----------------+-------------------+\n");
            printf("|%s    |%19d|\n", "MAC broadcast", table.mac_broad);
            printf("+-----------------+-------------------+\n");
            printf("|%s|%19d|\n", "Information speed", table.bps);
            printf("+-----------------+-------------------+\n");
            printf("|%s       |%19d|\n", "Code speed", table.btps);
            printf("+-----------------+-------------------+\n");
            printf("|%s      |%19d|\n", "ARP packets", table.arp_pkt);
            printf("+-----------------+-------------------+\n");
            printf("|%s       |%19d|\n", "IP packets", table.ip_pkt);
            printf("+-----------------+-------------------+\n");
            printf("|%s         |%19d|\n", "IP bytes", table.ip_byte);
            printf("+-----------------+-------------------+\n");
            printf("|%s     |%19d|\n", "IP broadcast", table.ip_broad);
            printf("+-----------------+-------------------+\n");
            printf("|%s      |%19d|\n", "TCP packets", table.tcp_pkt);
            printf("+-----------------+-------------------+\n");
            printf("|%s      |%19d|\n", "UDP packets", table.udp_pkt);
            printf("+-----------------+-------------------+\n");
            printf("|%s     |%19d|\n", "ICMP packets", table.icmp_pkt);
            printf("+-----------------+-------------------+\n");
            printf("|%s       |%19d|\n", "ICMP reply", table.icmp_rp);
            printf("+-----------------+-------------------+\n");
            printf("|%s    |%19d|\n", "ICMP redirect", table.icmp_rd);
            printf("+-----------------+-------------------+\n");
            printf("|%s     |%19d|\n", "ICMP request", table.icmp_rq);
            printf("+-----------------+-------------------+\n");
            printf("|%s |%19d|\n", "ICMP unreachable", table.icmp_du);
            printf("+-----------------+-------------------+\n");
            printf("User stopped.\n");

            sem_post(&sem_fin);
        default:
            break;
    }
}//TODO: ease the dead lock sometimes happens while network is busy