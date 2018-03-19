#include "main_header.h"

struct cntrl_header{
	uint8_t type;
	uint16_t circuit_id;
	uint16_t next_name;		
};

void circuit_creation(int n_routers, int m_hops){
	char control_message[30], buf[30];
	int numbytes;
	struct sockaddr_in my_addr;
    struct sockaddr_in incoming_addr;
    socklen_t incoming_addr_len = sizeof(struct sockaddr_in);

    for(int i=1;i<=m_hops;i++){
        memset(&control_message, 0, sizeof(control_message));
        memset(&buf, 0, sizeof(buf));
        struct iphdr *ip = (struct iphdr*) control_message;
        struct cntrl_header * cnt_h =  (struct cntrl_header *) (control_message+ sizeof(struct iphdr));
    
        //memset(&ip, 0x00, sizeof(ip));
        ip->saddr = inet_addr("127.0.0.1");
        ip->daddr = inet_addr("127.0.0.1");
        ip->protocol = 253;
        my_addr.sin_family = AF_INET;
        my_addr.sin_port = htons(port_number_router_int_global[0]);
        my_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        memset(my_addr.sin_zero,'\0',sizeof my_addr.sin_zero);
        socklen_t my_addr_len = sizeof(struct sockaddr_in);

        cnt_h->type = 0x52;
        cnt_h->circuit_id = 0x01;
        cnt_h->next_name = port_number_router_int_global[i];
        if(i==m_hops){
            cnt_h->next_name = 0xffff;
        }
        
        if ((numbytes = sendto(sockfd_proxy,control_message,30, 0,
                (struct sockaddr *)&my_addr, my_addr_len)) == -1) {
            perror("talker_circuit: sendto");
            exit(1);
        }
        if(i==1){
            fprintf(stderr, "Circuit: %d. Port-%d -> %d. Port-%u \n",i, port_number_proxy,i+1,port_number_router_int_global[0]);
        }
        else{
            fprintf(stderr, "Circuit: %d. Port-%d -> %d. Port-%u \n\n",i,port_number_router_int_global[i],i+1,port_number_router_int_global[i+1]);
        }


        if ((numbytes = recvfrom(sockfd_proxy, buf,30, 0,
                (struct sockaddr *)&incoming_addr, &(incoming_addr_len))) == -1) {
            perror("recvfrom_proxy_circuit");
            exit(1);
        }
        if(i==0){
            fprintf(stderr, "Circuit: %d. Port-%d -> %d. Port-%u \n",i, port_number_proxy,i+1,port_number_router_int_global[0]);
        }
        else{   
            fprintf(stderr, "Circuit: %d. Port-%d -> %d. Port-%u \n\n",i,port_number_router_int_global[i],i+1,port_number_router_int_global[i+1]);
        }    
    }

    printf("Circuit Completed %d\n", numbytes);
}