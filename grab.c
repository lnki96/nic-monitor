#include <linux/if_ether.h>
#include <netinet/in.h>
#include "data.h"
#include "grab.h"

static int mode, fd;
static u_int flen;
static fbundle frame;

int set_grabber(struct opts opt);
void fin_grabber();

void* grab(void* v) {
    mode = set_grabber(opt);

    if ((fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        printf("Cannot open socket: permission denied.\n");
        exit(ERR_PERMISSION_DENIED);
    } else {
        frame = init_fbundle();
        time(&frame.time);
        push_back_fq(&fque, &frame);
        while (1) {
            frame = init_fbundle();
            memset(frame.cont, '\0', sizeof(BUFFER_MAX));
            if (sig != SIGINT && (flen = recv(fd, frame.cont, BUFFER_MAX, 0)) > 0) {
                frame.len = flen;
                push_back_fq(&fque, &frame);
            } else
                break;
        }
        close(fd);
    }
    frame = init_fbundle();
    time(&frame.time);
    push_back_fq(&fque, &frame);

    fin_grabber();
    return v;
}

int set_grabber(struct opts opt){


    return 0;
}

void fin_grabber(){
    sem_post(&sem_complete);
//    if (fd < 0) {
//        for (int i = 0; i < 2; i++)
//            sem_wait(&sem_complete);
//        sem_post(&sem_fin);
//    }
}