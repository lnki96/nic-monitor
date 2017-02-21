//Logical fque of char*

#include "data.h"

fbundle init_fbundle(){
	fbundle frame;
	frame.len=0;
	frame.cont=(u_char*)calloc(sizeof(u_char),BUFFER_MAX);

	return frame;
}

void destroy_fbundle(fbundle* frame){
	free(frame->cont);
}

frame_que init_fq(){
	frame_que head;
	head.frame.len=0;
	head.frame.cont=NULL;
	head.next=NULL;
	head.prev=head.next;
	return head;
}

int push_back_fq(frame_que* fque, const fbundle* frame){
	pthread_mutex_lock(&mutex_fq);
	if(LIST_MAX==0||fque->frame.len<=LIST_MAX){
		if(fque->frame.len==0){
			fque->next=(frame_que*)malloc(sizeof(frame_que));
			fque->prev=NULL;
			fque->next->next=fque->next;
			fque->next->prev=fque->next;
		}
		else{
			frame_que* temp=(frame_que*)malloc(sizeof(frame_que));
			fque->next->prev->next=temp;
			fque->next->prev->next->next=fque->next;
			fque->next->prev->next->prev=fque->next->prev;
			fque->next->prev=fque->next->prev->next;
		}
		++fque->frame.len;
		fque->next->prev->frame=*frame;
		sem_post(&sem_fq);
	}
	pthread_mutex_unlock(&mutex_fq);

	return 0;
}

fbundle* pop_front_fq(frame_que* fque, fbundle* frame){
	sem_wait(&sem_fq);
	pthread_mutex_lock(&mutex_fq);
	frame_que* temp;

	if(fque->frame.len>0){
		frame->time=fque->next->frame.time;
		frame->len=fque->next->frame.len;
		frame->cont=fque->next->frame.cont;
		temp=fque->next;
		if(fque->frame.len>1){
			fque->next->next->prev=fque->next->prev;
			fque->next->prev->next=fque->next->next;
			fque->next=fque->next->next;
		} else {
			fque->next=NULL;
		}
		--fque->frame.len;
		free(temp);
	}
	pthread_mutex_unlock(&mutex_fq);

	return frame;
}

void destroy_fq(frame_que* fque){
	frame_que* ptr=fque->next;
	for(int i=0;i<fque->frame.len;i++){
		destroy_fbundle(&ptr->frame);
		free(ptr);
		ptr=ptr->next;
	}
}

bundle init_bundle(){
	bundle bd;
    bd.valid=1;
	bd.str_list=NULL;
	bd.ui_list=NULL;
	return bd;
}

int put_string(bundle* bd, const string k, const string v, const u_int len){
	struct s_b_list* temp=(struct s_b_list*)malloc(sizeof(struct s_b_list));
	temp->key=(char*)calloc(sizeof(char),strlen(k)+1);
	temp->val=(char*)calloc(sizeof(char),len+1);
	memcpy(temp->key,k,strlen(k));
	memcpy(temp->val,v,len);
	temp->key[strlen(k)]='\0';
	temp->val[len]='\0';
	temp->len=len;
	temp->next=bd->str_list;
	bd->str_list=temp;

	return 0;
}

int get_string(const bundle* bd, const string k, string v, const u_int len){
	struct s_b_list* temp=bd->str_list;
	while(temp){
		if(!strcmp(temp->key,k)){
			memcpy(v,temp->val,temp->len<len?temp->len:len);
			return 0;
		}
		temp=temp->next;
	}

	return -1;
}

int put_u_int(bundle* bd, string k, const u_int v){
	struct ui_b_list* temp=(struct ui_b_list*)malloc(sizeof(struct ui_b_list));
	temp->key=(char*)calloc(sizeof(char),strlen(k)+1);
	strcpy(temp->key,k);
    temp->key[strlen(k)]='\0';
	temp->val=v;
	temp->next=bd->ui_list;
	bd->ui_list=temp;

	return 0;
}

int get_u_int(const bundle* bd, string k, u_int* v){
	struct ui_b_list* temp=bd->ui_list;
	while(temp!=NULL){
		if(!strcmp(temp->key,k)){
			*v=temp->val;
            return 0;
		}
		temp=temp->next;
	}

	return -1;
}

void destroy_bd(bundle* bd){
	struct s_b_list* str_list=bd->str_list;
	struct ui_b_list* ui_list=bd->ui_list;
	while(str_list!=NULL){
		bd->str_list=str_list->next;
		free(str_list->key);
		free(str_list->val);
		free(str_list);
		str_list=bd->str_list;
	}
	while(ui_list!=NULL){
		bd->ui_list=ui_list->next;
		free(ui_list->key);
		free(ui_list);
		ui_list=bd->ui_list;
	}
}

bd_que init_bdq(){
	bd_que head;
	head.bd.ui_list=(struct ui_b_list*)malloc(sizeof(struct ui_b_list));
	head.bd.ui_list->val=0;
	head.next=NULL;
	head.prev=head.next;
	return head;
}

int push_back_bdq(bd_que* bdque, const bundle* bd){
	pthread_mutex_lock(&mutex_bdq);
	if(LIST_MAX==0||bdque->bd.ui_list->val<=LIST_MAX){
		if(bdque->bd.ui_list->val==0){
			bdque->next=(bd_que*)malloc(sizeof(bd_que));
			bdque->prev=NULL;
			bdque->next->next=bdque->next;
			bdque->next->prev=bdque->next;
		}
		else{
			bd_que* temp=(bd_que*)malloc(sizeof(bd_que));
			bdque->next->prev->next=temp;
			bdque->next->prev->next->next=bdque->next;
			bdque->next->prev->next->prev=bdque->next->prev;
			bdque->next->prev=bdque->next->prev->next;
		}
		++bdque->bd.ui_list->val;
		bdque->next->prev->bd=*bd;
		sem_post(&sem_bdq);
	}
	pthread_mutex_unlock(&mutex_bdq);

	return 0;
}

bundle* pop_front_bdq(bd_que* bdque, bundle* bd){
	sem_wait(&sem_bdq);
	pthread_mutex_lock(&mutex_bdq);
	bd_que* temp;

	if(bdque->bd.ui_list->val>0){
        bd->valid=bdque->next->bd.valid;
        bd->time=bdque->next->bd.time;
		bd->str_list=bdque->next->bd.str_list;
		bd->ui_list=bdque->next->bd.ui_list;
		temp=bdque->next;
		if(bdque->bd.ui_list->val>1){
			bdque->next->next->prev=bdque->next->prev;
			bdque->next->prev->next=bdque->next->next;
			bdque->next=bdque->next->next;
		} else {
			bdque->next=NULL;
		}
		--bdque->bd.ui_list->val;
		free(temp);
	}
	pthread_mutex_unlock(&mutex_bdq);

	return bd;
}

void destroy_bdq(bd_que* bdque){
	bd_que* ptr=bdque->next;
	for(int i=0;i<bdque->bd.ui_list->val;i++){
		destroy_bd(&ptr->bd);
		free(ptr);
		ptr=ptr->next;
	}
}

stats init_stats(){
	stats table;

	table.frame_short=0;
	table.frame_long=0;
	table.frame_normal=0;

	table.mac_broad=0;
//	table.mac_short=0;
//	table.mac_long=0;
//	table.mac_byte=0;
	table.bps=0;
	table.btps=0;
	table.arp_pkt=0;
	table.ip_broad=0;
	table.ip_byte=0;
	table.ip_pkt=0;
	table.tcp_pkt=0;
	table.udp_pkt=0;
	table.icmp_pkt=0;
	table.icmp_rd=0;
	table.icmp_rp=0;
	table.icmp_rq=0;
	table.icmp_du=0;

	return table;
}

mac_list init_list() {
    mac_list mlist;
    mlist.mac = NULL;
    mlist.next = NULL;

    return mlist;
}

int insert_list(mac_list* mlist, u_string mac) {
	if (!mlist->mac) {
		mlist->mac = (u_char *) calloc(sizeof(u_char), 7);
		memcpy(mlist->mac, mac, 6);
	} else {
        mac_list *temp = (mac_list *) malloc(sizeof(mac_list));
        int cmp;
        temp->mac = (u_char *) calloc(sizeof(u_char), 7);
        memcpy(temp->mac, mac, 6);
        temp->mac[6] = '\0';
        if ((cmp = memcmp(mlist->mac, mac, 6)) > 0) {
            u_string mac_tmp = mlist->mac;
            mlist->mac = temp->mac;
            temp->mac = mac_tmp;

            temp->next = mlist->next;
            mlist->next = temp;
        } else if (cmp) {
            while (mlist->next && (cmp = memcmp(mlist->next->mac, mac, 6)) < 0)
                mlist = mlist->next;
            if(cmp) {
                temp->next = (mlist->next)?mlist->next:NULL;
                mlist->next = temp;
            }
        }
    }

	return 0;
}

void destroy_list(mac_list* mlist){
	mac_list* temp=mlist;
	while(!mlist){
		free(mlist->mac);
		mlist=mlist->next;
		free(temp);
		temp=mlist;
	}
}
