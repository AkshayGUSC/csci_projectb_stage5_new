#include "main_header.h"

FILE *out_proxy;

struct relay_header{
    uint8_t type;
    uint16_t circuit_id;
};

// copied the entire code for calculating checksum from http://www.microhowto.info/howto/calculate_an_internet_protocol_checksum_in_c.html#idp22752
uint16_t ip_checksum(void* vdata,size_t length) {
    // Cast the data pointer to one that can be indexed.
    char* data=(char*)vdata;

    // Initialise the accumulator.
    uint32_t acc=0xffff;

    // Handle complete 16-bit blocks.
    for (size_t i=0;i+1<length;i+=2) {
        uint16_t word;
        memcpy(&word,data+i,2);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Handle any partial block at the end of the data.
    if (length&1) {
        uint16_t word=0;
        memcpy(&word,data+length-1,1);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Return the checksum in network byte order.
    return htons(~acc);
}
int tun_alloc(char *dev, int flags) 
{
    struct ifreq ifr;
    int fd, err;
    char *clonedev = (char*)"/dev/net/tun";

    if( (fd = open(clonedev , O_RDWR)) < 0 ) 
    {
    perror("Opening /dev/net/tun");
    return fd;
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = flags;

    if (*dev) 
    {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) 
    {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
    }

    strcpy(dev, ifr.ifr_name);
    return fd;
}


int tunnel_reader()
{
    char tun_name[IFNAMSIZ];
    char buffer[88];
    char buf1[88];
    int n, numbytes;
    struct sockaddr_in my_addr;
    int rv =0;
    /* Connect to the tunnel interface (make sure you create the tunnel interface first) */
    strcpy(tun_name, "tun1");
    int tun_fd = tun_alloc(tun_name, IFF_TUN | IFF_NO_PI);

    if(tun_fd < 0)
    {
        perror("Open tunnel interface");
        exit(1);
    }

    n = tun_fd + 1;     

    while(1) 
    {
        struct timeval tv;
        fd_set readfds;

        tv.tv_sec = 7;
        tv.tv_usec = 500000;

        FD_ZERO(&readfds);
        FD_SET(sockfd_proxy, &readfds);
        FD_SET(tun_fd, &readfds);


        rv = select(n, &readfds, NULL, NULL, &tv);


        if (rv == -1) {
            perror("select"); // error occurred in select()
        } 
        else if(rv == 0){
            fprintf(stderr, "exiting proxy\n");
            fclose(out_proxy);
            char close_router[10];
            sprintf(close_router,"%s","-1\0");
            for(int i=0;i<number_routers;i++){ 

                struct sockaddr_in send_addr;
                send_addr.sin_family = AF_INET;
                send_addr.sin_port = htons(port_number_router_int_global[i]);
                send_addr.sin_addr.s_addr = address_list_global[i];
                memset(send_addr.sin_zero,'\0',sizeof send_addr.sin_zero);

                fprintf(stderr,"now sending from main_program.c\n");
                fprintf(stderr, "address is %u and port number is %d\n",address_list_global[i], port_number_router_int_global[i]);

                if ((numbytes = sendto(sockfd_proxy,close_router,strlen(close_router), 0,
                            (struct sockaddr *)&send_addr, sizeof send_addr)) == -1) {
                    perror("talker_PROXY: sendto");
                    exit(1);
                }
            }   
            close(sockfd_proxy);
            exit(0);
        } 
        else {
        // one or both of the descriptors have data
            if (FD_ISSET(sockfd_proxy, &readfds)) {

                recv(sockfd_proxy, buf1, 88, 0);

                struct relay_header *relay_data = (struct relay_header*)(buf1);

                fprintf(stderr, "In proxy, type=%x, id=%x\n", relay_data->type, relay_data->circuit_id);

                char buf_write[84];
                for(int i=0;i<84;i++){
                    buf_write[i] = buf1[4+i];
                }

                struct iphdr *ip = (struct iphdr *)(buf_write);
                ip->daddr = inet_addr("10.0.2.15");
                ip->check = 0;           
                ip->check = ip_checksum(ip,20);
                fprintf(stderr, "writing back to tunnel\n");


                write(tun_fd, buf_write, 84);
            }
            if (FD_ISSET(tun_fd, &readfds)) {

                /* Now read data coming from the tunnel */
                int nread = read(tun_fd,buffer,sizeof(buffer));

                if(nread < 0) 
                {
                    perror("Reading from tunnel interface");
                    close(tun_fd);
                    exit(1);
                }
                else
                {                    
                    struct iphdr *ip = (struct iphdr *)(buffer);
                    struct icmphdr *icmp = (struct icmphdr *)(buffer+sizeof(struct iphdr));
                    fprintf(stderr, "Read a packet from tunnel, packet length:%d, dest address=%s\n", 
                        nread, inet_ntoa(*(struct in_addr*)&ip->daddr));

                    if(icmp->type == 8){

                        char buf_whole[88];
                        memset(&buf_whole,0,sizeof buf_whole);

                        struct relay_header *relay_data = (struct relay_header*)(buf_whole);
                        relay_data->type = 0x51;
                        relay_data->circuit_id = 0x01;

                        for(int i=0;i<84;i++){
                            buf_whole[4+i] = buffer[i];
                        }

                        fprintf(stderr, "In proxy: type=0x%x and circuit_id=0x%x\n",relay_data->type , relay_data->circuit_id);

                        fprintf(out_proxy, "ICMP from tunnel, src: 10.0.2.15, dst: %s, type: 8\n",inet_ntoa(*(struct in_addr*)&ip->daddr));

                        int index = ntohl(ip->daddr) % number_routers; 
                        index++;
                        fprintf(stderr, "index value hashmap = %d\n", index);
                        fflush(NULL);
                        my_addr.sin_family = AF_INET;
                        my_addr.sin_port = htons(port_number_router_int_global[index-1]);
                        my_addr.sin_addr.s_addr = address_list_global[index-1];
                        memset(my_addr.sin_zero,'\0',sizeof my_addr.sin_zero);
                        fprintf(stderr, "port number =%d and address =%u\n",port_number_router_int_global[index-1],address_list_global[index-1]);
                        if ((numbytes = sendto(sockfd_proxy,buf_whole,88, 0,
                            (struct sockaddr *)&my_addr, sizeof my_addr)) == -1) {
                            perror("talker_PROXY: sendto");
                            exit(1);
                        }                     
                    }
                }

            }
        }

    
    }
}

int main(int argc, char** argv)
{
    address_list_global[0]=inet_addr("10.0.3.15");
    address_list_global[1]=inet_addr("10.0.4.15");
    address_list_global[2]=inet_addr("10.0.5.15");
    address_list_global[3]=inet_addr("10.0.6.15");
    address_list_global[4]=inet_addr("10.0.7.15");
    address_list_global[5]=inet_addr("10.0.8.15"); 

    number_routers = read_file(argv[1]);

    sockfd_proxy = server_connection();
    // Starting the index with 1 so for accessing router do index-1
    for(int index_router =1; index_router<=number_routers;index_router++){
        if (fork() == 0){
            client_connection(index_router);
        }
        else{
            char buf[100];
            int numbytes;
            struct sockaddr_storage their_addr_router;
            socklen_t addr_len_router;

            addr_len_router = sizeof their_addr_router;

            if ((numbytes = recvfrom(sockfd_proxy, buf, 100-1, 0,
                (struct sockaddr *)&their_addr_router, &addr_len_router)) == -1) {

                perror("recvfrom_proxy");
                exit(1);
            }
            int i=0;

        while(buf[i]>=48 && buf[i]<=57){
            pid_router_char[i] = buf[i];
            i++;
        }
        pid_router_char[i] = '\0';
        char port_number_router_char[strlen(buf)-i];
        int index=0;
        for(int k=i+1;k<strlen(buf);k++){ 
            port_number_router_char[index] = buf[k];
            index++;
        }
        port_number_router_char[index] = '\0';

        ////////////////////////////
        port_number_router_int_global[index_router-1] = atoi(port_number_router_char);
        fprintf(out_proxy,"router:%d, pid:%s, port:%d\n",index_router,pid_router_char, port_number_router_int_global[index_router-1]);
        fflush(NULL);
        }  
    }
    circuit_creation(number_routers,6); 
    tunnel_reader();  
    close(sockfd_proxy);
    return 0;
}
