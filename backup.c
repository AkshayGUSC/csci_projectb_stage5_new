#include "main_header.h"

struct cntrl_header{
    uint8_t type;
    uint16_t circuit_id;
    uint16_t next_name;     
};

struct relay_header{
    uint16_t type;
    uint16_t circuit_id;   
};

uint16_t in_c_id;
uint16_t out_c_id;
uint16_t in_port;
uint16_t out_port;
int client_connection(int x){

    int sockfd, sockfd_raw, sockfd_loopback;
    int rv, n;
    int numbytes;
    struct sockaddr_in their_addr, binding, router_addr, send_addr;
    socklen_t addr_len = sizeof(struct sockaddr);
    struct ifreq ifr;
    char router_ip[14];
    int flag_extend =1;
    address_list_global[0]=inet_addr("10.0.3.15");
    address_list_global[1]=inet_addr("10.0.4.15");
    address_list_global[2]=inet_addr("10.0.5.15");
    address_list_global[3]=inet_addr("10.0.6.15");
    address_list_global[4]=inet_addr("10.0.7.15");
    address_list_global[5]=inet_addr("10.0.8.15");
    if(x == 1){
        strncpy(router_ip,"10.0.3.15\0",14);
    }
    else if (x == 2){
        strncpy(router_ip,"10.0.4.15\0",14);
    }
    else if (x == 3){
        strncpy(router_ip,"10.0.5.15\0",14);
    }
    else if (x == 4){
        strncpy(router_ip,"10.0.6.15\0",14);
    }
    else if (x == 5){
        strncpy(router_ip,"10.0.7.15\0",14);
    }
    else if (x == 6){
        strncpy(router_ip,"10.0.8.15\0",14);
    }

    /* update the IP address List*/
    address_list_global[x-1] = inet_addr(router_ip);

    /*sockfd is binded to the routers IP address for UDP*/
    if ((sockfd = socket(AF_INET, SOCK_DGRAM,0)) == -1) {
            perror("Router: UDP socket");
    }  
    router_addr.sin_addr.s_addr = inet_addr(router_ip);
    router_addr.sin_family = AF_INET;
    router_addr.sin_port = htons(0);
    if (bind(sockfd, (struct sockaddr *)&router_addr, sizeof(router_addr)) == -1) {
        close(sockfd);
        perror("Bind to IP ERROR:  UDP sockfd");
    }
    /* Getting the router UDP port number*/
    char child_pid[100];
    sprintf(child_pid,"%d", getpid());
    struct sockaddr_in socket_addr;
    socklen_t length = sizeof(socket_addr);

    if(getsockname(sockfd, (struct sockaddr *)&socket_addr,&length) == -1){
        perror("error in getsocketname()");
        exit(-1);
    }
    port_number_router = (int)ntohs(socket_addr.sin_port);

    sprintf(child_pid+strlen(child_pid),"a");
    sprintf(child_pid+strlen(child_pid),"%d", port_number_router);

    /*sockfd_raw is binded to the routers IP address & also ethernet interface for Internet*/
    if ((sockfd_raw = socket(AF_INET, SOCK_RAW,
            IPPROTO_ICMP)) == -1) {
        perror("talker: raw socket");
    }     
    char interface_index[10];
    sprintf(interface_index,"eth"); 
    sprintf(interface_index+strlen(interface_index),"%d",x); 
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name),interface_index);
    fprintf(stderr,"router ip address %s binded to %s\n", router_ip,interface_index);
    if((rv = setsockopt(sockfd_raw, SOL_SOCKET, SO_BINDTODEVICE, (void*)&ifr, sizeof(ifr)))<0){
        perror("Router-error binding to eth1: sockfd_raw");
        close(sockfd_raw);
        exit(-1);
    }       
    binding.sin_addr.s_addr = inet_addr(router_ip);
    binding.sin_family = AF_INET;
    binding.sin_port = htons(0);
    if (bind(sockfd_raw, (struct sockaddr *)&binding, sizeof(binding)) == -1) {
        close(sockfd_raw);
        perror("listener: raw bind");
    }

    /*sockfd_loopback is binded to the loopback address on same port as UDP for circuit creation*/
    if ((sockfd_loopback = socket(AF_INET, SOCK_DGRAM,0)) == -1) {
            perror("Router: UDP socket");
    } 
    router_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    router_addr.sin_family = AF_INET;
    router_addr.sin_port = htons(port_number_router);
    if (bind(sockfd_loopback, (struct sockaddr *)&router_addr, sizeof(router_addr)) == -1) {
        close(sockfd);
        perror("Bind to IP ERROR:  UDP sockfd");
    }

    char filename[100];
    sprintf(filename,"stage4.router");
    sprintf(filename+strlen(filename),"%d",x);
    sprintf(filename+strlen(filename),".out");

    FILE *out_router = fopen(filename,"w+");
    fprintf(out_router,"router:%d, pid:%d, port:%d IP Address:%s\n", x, getpid(), port_number_router, router_ip);
    fflush(NULL);

    send_addr.sin_family = AF_INET;
    send_addr.sin_port = htons(port_number_proxy);
    send_addr.sin_addr.s_addr = inet_addr("10.0.2.15");
    memset(send_addr.sin_zero,'\0',sizeof send_addr.sin_zero);

    if ((numbytes = sendto(sockfd,child_pid,strlen(child_pid), 0,
         (struct sockaddr *)&send_addr, sizeof send_addr)) == -1) {
        perror("talker_router_config_info_to_proxy: sendto");
        exit(1);
    }
    
    char buffer[88];

    n = sockfd_loopback +1;
    while(1){

        fd_set readfds;

        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);
        FD_SET(sockfd_raw, &readfds);
        FD_SET(sockfd_loopback, &readfds);

        rv = select(n, &readfds, NULL, NULL, NULL);

        if (rv == -1) {
            perror("select"); // error occurred in select()
        }

        else{
            // ICMP packet coming from proxy
            if (FD_ISSET(sockfd, &readfds)) {

                memset(&buffer, 0, sizeof buffer);

                if ((numbytes = recvfrom(sockfd, buffer, 88, 0,
                    (struct sockaddr *)&their_addr, &addr_len)) == -1) {
                    perror("recvfrom");
                    exit(1);
                }

                if(buffer[0] == '-'){
                    fprintf(stderr, "Exiting router Message received %c\n", buffer[0]);
                    fclose(out_router);
                    close(sockfd);
                    close(sockfd_raw);
                    exit(0);
                }

                struct relay_header *relay_data = (struct relay_header*)(buffer);
                struct iphdr *ip = (struct iphdr *)(buffer+sizeof(struct relay_header));
                struct icmphdr *icmp = (struct icmphdr *)(buffer+sizeof(struct iphdr)+ sizeof(struct relay_header));
                char *some_addr;
                some_addr = inet_ntoa(*(struct in_addr*)&ip->daddr);
                fprintf(stderr, "In Router, destination ip address = %s\n",some_addr);
                fprintf(out_router, "ICMP from port: %d, src: 10.0.2.15, dst: %s, type: 8\n",port_number_proxy, inet_ntoa(*(struct in_addr*)&ip->daddr));
                fflush(NULL);
                fprintf(stderr, "In router %d, in_c_id=%u, out_c_id=%u out_port=%u",(x),in_c_id, out_c_id, out_port);

                fprintf(stderr, "In router %d, type=%u, id=%u\n",(x),relay_data->type, relay_data->circuit_id);
                

                if((relay_data->type == 81) && (relay_data->circuit_id == in_c_id)){
                    if(out_port == 65535){
                        // sendmsg format referred from http://www.microhowto.info/howto/send_an_arbitrary_ipv4_datagram_using_a_raw_socket_in_c.html
                        ip->saddr = inet_addr(router_ip);
                        their_addr.sin_addr.s_addr = ip->daddr;
                        fprintf(stderr, "sending internet address destination id =%s\n",inet_ntoa(*(struct in_addr*)&ip->daddr));
                        fprintf(stderr, "sending internet address source id =%s\n",inet_ntoa(*(struct in_addr*)&ip->saddr));
                        char buffer_tosend[84];
                        for(int i=0;i<84;i++){
                            buffer_tosend[i] = buffer[4+i]; 
                        }
                        struct msghdr buf;
                        struct iovec iov[1];
                        iov[0].iov_base= icmp;
                        iov[0].iov_len= sizeof(buffer_tosend) - sizeof(struct iphdr);
                        buf.msg_name= &(their_addr); // here their_addr is sockaddr_in
                        buf.msg_namelen= sizeof(struct sockaddr);
                        buf.msg_iov= iov;
                        buf.msg_iovlen= 1;
                        buf.msg_control=0;
                        buf.msg_controllen=0;
                        if ((numbytes = sendmsg(sockfd_raw,&buf, 0)) == -1) {
                            perror("talker_router _hello: sendmsg");
                            exit(1);
                        }
                        fprintf(stderr,"!!!!! woooowwww raw sent numbytes = %d\n",numbytes);
                        fflush(NULL); 
                    }
                    else{
                        fprintf(stderr, "Relay data to router %d out_c_id=%u\n",(x+1),out_c_id);
                        ip->saddr = inet_addr(router_ip);
                        relay_data->circuit_id = out_c_id;
                        struct sockaddr_in forward_addr;
                        forward_addr.sin_family = AF_INET;
                        forward_addr.sin_port = htons(out_port);
                        forward_addr.sin_addr.s_addr = address_list_global[x]; // forward to index+1 router
                        memset(forward_addr.sin_zero,'\0',sizeof forward_addr.sin_zero);
                        fprintf(stderr, "Relay data to router %d out_c_id=%u\n",(x+1), relay_data->circuit_id);

                        if ((numbytes = sendto(sockfd,buffer,88, 0,
                            (struct sockaddr *)&forward_addr, sizeof forward_addr)) == -1) {
                            perror("talker_router_relaydata_to_next_router: sendto");
                            exit(1);
                        }
                    }
                } 
                else{
                    fprintf(stderr, "The packet is not having correct id\n");
                    continue;
                }       
            }
            //icmp packet coming from internet at raw socket
            if (FD_ISSET(sockfd_raw, &readfds)) {

                printf("Receiving at raw socket from Internet\n");
                char buffer_torecv[84];
                memset(&buffer_torecv, 0, sizeof buffer_torecv);
                struct msghdr buf;
                struct iovec iov[1];
                iov[0].iov_base = buffer_torecv;
                buf.msg_iov = iov;
                iov[0].iov_len= sizeof(buffer_torecv);
                buf.msg_iovlen= 1;

                if ((numbytes = recvmsg(sockfd_raw, &buf, 0)) == -1) {
                    perror("recvfrom from raw scoket");
                    exit(1);
                }                
                fprintf(stderr, "Message from Internet = %d\n", numbytes);
                struct iphdr *ip = (struct iphdr *)(buffer_torecv);

                fprintf(out_router, "ICMP from raw sock, src: %s, dst: %s, type: 0\n", inet_ntoa(*(struct in_addr*)&ip->saddr), router_ip);
                fflush(NULL);
                fprintf(out_proxy, "ICMP from port: %d, src: %s, dst: 10.0.2.15, type: 0\n",port_number_proxy, inet_ntoa(*(struct in_addr*)&ip->saddr));
                fflush(NULL);

                memset(&buffer, 0, sizeof buffer);
                struct relay_header *relay_data = (struct relay_header*)(buffer);
                relay_data->type = 0x54;
                relay_data->circuit_id = out_c_id;

                for(int i=0;i<84;i++){
                    buffer[4+i] = buffer_torecv[i];
                }
                
                if ((numbytes = sendto(sockfd,buffer,88, 0,
                        (struct sockaddr *)&send_addr, sizeof send_addr)) == -1) {
                    perror("talker_router: sendto");
                    exit(1);
                }   
            }

            if (FD_ISSET(sockfd_loopback, &readfds)) {

                char incoming_buf[30];
                struct sockaddr_in incoming_addr;
                socklen_t incoming_addr_len = sizeof(struct sockaddr_in);
                memset(&incoming_buf, 0, sizeof incoming_buf);

                if ((numbytes = recvfrom(sockfd_loopback, incoming_buf,30, 0,
                    (struct sockaddr *)&incoming_addr, &incoming_addr_len)) == -1) {
                    perror("recvfrom in scokfd_loopback");
                    exit(1);
                }

                struct iphdr *ip = (struct iphdr *)(incoming_buf);
                fprintf(stderr, "Inside loopback router#%d ip->protocol=%u\n",x,ip->protocol);
                if(ip->protocol == 253){
                    fprintf(stderr,"coming inside protocol\n");
                    struct cntrl_header * cnt_h =  (struct cntrl_header *) (incoming_buf + sizeof(struct iphdr));
                    struct sockaddr_in send_addr;
                    socklen_t addr_len = sizeof(struct sockaddr);
                    // in circuit extend stage only for router 1
                    if((cnt_h->type == 0x52) && (flag_extend == 1) && (x==1)){
                        in_c_id = cnt_h->circuit_id;
                        out_c_id = x*256 +1;
                        in_port = ntohs(incoming_addr.sin_port);
                        out_port = cnt_h->next_name;
                        cnt_h->type = 0x53;
                        
                        send_addr.sin_addr.s_addr = inet_addr("10.0.2.15");
                        send_addr.sin_family = AF_INET;
                        send_addr.sin_port = htons(in_port);
                        fprintf(stderr,"**In router:%d, Circuit Extend:IID=0x%x OID=0x%x,Incoming Port=%u Outgoing Port=%u Next_Hop=%u\n",x,in_c_id,out_c_id,in_port, out_port, cnt_h->next_name);
                        if ((numbytes = sendto(sockfd,incoming_buf,30, 0,
                                (struct sockaddr *)&send_addr, addr_len)) == -1) {
                            perror("talker_router_circuit: sendto");
                            exit(1);
                        }
                        flag_extend =0;
                    }
                    else if((cnt_h->type == 0x52) && (flag_extend == 1) && (x!=1)){
                        in_c_id = cnt_h->circuit_id;
                        out_c_id = (x)*256 +1;
                        in_port = ntohs(incoming_addr.sin_port);
                        out_port = cnt_h->next_name;
                        cnt_h->type = 0x53;                       
                        send_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
                        send_addr.sin_family = AF_INET;
                        send_addr.sin_port = htons(in_port);
                        fprintf(stderr,"!!In router:%d, Circuit Extend:IID=0x%x OID=0x%x,Incoming Port=%u Outgoing Port=%u Next_Hop=%u\n",x, in_c_id,out_c_id,in_port,out_port,cnt_h->next_name);
                        if ((numbytes = sendto(sockfd,incoming_buf,30, 0,
                                (struct sockaddr *)&send_addr, addr_len)) == -1) {
                            perror("talker_router_circuit: sendto");
                            exit(1);
                        }
                        flag_extend =0;
                    }
                    // in forwarding stage
                    else{
                        if((cnt_h->type == 0x52) && (flag_extend == 0)){
                            send_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
                            send_addr.sin_family = AF_INET;
                            send_addr.sin_port = htons(out_port);
                            fprintf(stderr,"**In router:%d, Forwarding Circuit Extend:IID=0x%x OID=0x%x,Incoming Port=%u Outgoing Port=%u Next_Hop=%u\n",x, in_c_id, out_c_id, in_port,out_port,cnt_h->next_name);
                            cnt_h->circuit_id = out_c_id;
                            if ((numbytes = sendto(sockfd,incoming_buf,30, 0,
                                    (struct sockaddr *)&send_addr, addr_len)) == -1) {
                                perror("talker_router_circuit: sendto");
                                exit(1);
                            }
                        }
                        else if((cnt_h->type == 0x53) && (x!=1)){
                            send_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
                            send_addr.sin_family = AF_INET;
                            send_addr.sin_port = htons(in_port);

                            fprintf(stderr,"**In router:%d, Forwarding Reply:IID=0x%x OID=0x%x,Incoming Port=%u Outgoing Port=%u Next_Hop=%u\n",x, in_c_id, out_c_id, in_port,out_port, cnt_h->next_name);
                            if ((numbytes = sendto(sockfd,incoming_buf,30, 0,
                                    (struct sockaddr *)&send_addr, addr_len)) == -1) {
                                perror("talker_router_circuit: sendto");
                                exit(1);
                            }
                        }
                        else if((cnt_h->type == 0x53) && (x==1)){
                            send_addr.sin_addr.s_addr = inet_addr("10.0.2.15");
                            send_addr.sin_family = AF_INET;
                            send_addr.sin_port = htons(in_port);
                            fprintf(stderr,"!!In router:%d, Forwarding Reply:IID=0x%x OID=0x%x,Incoming Port=%u Outgoing Port=%u Next_Hop=%u\n",x, in_c_id, out_c_id, in_port,out_port, cnt_h->next_name);
                            if ((numbytes = sendto(sockfd,incoming_buf,30, 0,
                                    (struct sockaddr *)&send_addr, addr_len)) == -1) {
                                perror("talker_router_circuit: sendto");
                                exit(1);
                            }
                        }
                        flag_extend =0;
                    }
                }

            }
        }  
    }
    close(sockfd);  
    exit(0);
}