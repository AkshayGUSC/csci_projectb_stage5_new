#include "main_header.h"


int port_number_proxy;
int port_number_router;
int sockfd_proxy;
char port_number_router_char_global[100];
FILE *out_proxy, *out_router;
char pid_router_char[100];
    char n_router[50];      
    char stage;

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
    char buffer[2048];
    char buf1[2048];
    int n, numbytes;

    /* Connect to the tunnel interface (make sure you create the tunnel interface first) */
    strcpy(tun_name, "tun1");
    int tun_fd = tun_alloc(tun_name, IFF_TUN | IFF_NO_PI);

    if(tun_fd < 0)
    {
        perror("Open tunnel interface");
        exit(1);
    }

    out_proxy = fopen("stage1.proxy.out","w+");
    fprintf(out_proxy,"proxy port: %d\nrouter:1, pid:%s, port:%s\n",port_number_proxy,pid_router_char, port_number_router_char_global);

    out_router = fopen("stage1.router1.out","w+");
    fprintf(out_router,"router:1, pid:%s, port:%s\n",pid_router_char, port_number_router_char_global);
    
    /* Taken the select() code from Beej*/

    struct addrinfo hints, *p, *clientinfo;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // set to AF_INET to force IPv4
    hints.ai_socktype = SOCK_DGRAM;
    //hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo("192.168.201.2", port_number_router_char_global, &hints, &clientinfo)) != 0) {
        fprintf(stderr, "getaddrinfo _router1: %s\n", gai_strerror(rv));
        exit(1);
    }

    p = clientinfo;
    

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
            printf("exiting proxy\n");
            fclose(out_proxy);
            fclose(out_router);
            char close_router[10];
            sprintf(close_router,"%s","1\0");
            if ((numbytes = sendto(sockfd_proxy,close_router,strlen(close_router), 0,
                            p->ai_addr, p->ai_addrlen)) == -1) {
                    perror("talker_PROXY: sendto");
                    exit(1);
            }
            exit(0);
        } 
        else {
        // one or both of the descriptors have data
            if (FD_ISSET(sockfd_proxy, &readfds)) {
                recv(sockfd_proxy, buf1, 84, 0);
                struct iphdr *ip = (struct iphdr *)(buf1);
                struct sockaddr_in dest_change, src_change;
                inet_aton("10.0.2.15", &dest_change.sin_addr); 
                inet_aton("128.30.2.32", &src_change.sin_addr); 
                ip->daddr = dest_change.sin_addr.s_addr;
                ip->saddr = src_change.sin_addr.s_addr;
                printf("RECCCCCCCCEIVED BY PROXY src address=%s\n", inet_ntoa(*(struct in_addr*)&ip->saddr));
                fprintf(out_proxy, "ICMP from port: %s, src: %s, dst: 10.5.51.2, type: 0\n",port_number_router_char_global, inet_ntoa(*(struct in_addr*)&ip->saddr));

                write(tun_fd, buf1, 84);

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
                    //printf("Read a packet from tunnel, packet length:%d\n", nread);
                    
                    struct iphdr *ip = (struct iphdr *)(buffer);
                    struct icmphdr *icmp = (struct icmphdr *)(buffer+sizeof(struct iphdr));
                    printf("Read a packet from tunnel, packet length:%d, src address=%s\n", nread, inet_ntoa(*(struct in_addr*)&ip->saddr));

                    if(icmp->type == 8){
                        fprintf(out_proxy, "ICMP from tunnel, src: 10.5.51.2, dst: %s, type: 8\n",inet_ntoa(*(struct in_addr*)&ip->daddr));
                        fprintf(out_router, "ICMP from port: %d, src: 10.5.51.2, dst: %s, type: 8\n",port_number_proxy, inet_ntoa(*(struct in_addr*)&ip->daddr));
                        if ((numbytes = sendto(sockfd_proxy,buffer,nread, 0,
                            p->ai_addr, p->ai_addrlen)) == -1) {
                            perror("talker_PROXY: sendto");
                            exit(1);
                        }
                    }

                }

            }
        }

    
    }
    freeaddrinfo(clientinfo);

}
int server_connection(){
    /*Socket connection code copied from BEEJ TUTORIAL*/
    struct addrinfo hints, *servinfo, *p;
    int rv;
    int sockfd;
    
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // set to AF_INET to force IPv4
    hints.ai_socktype = SOCK_DGRAM;

    if ((rv = getaddrinfo("10.0.2.15", "0", &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo_server: %s\n", gai_strerror(rv));
        exit(1);
    }   
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("listener: socket");
            continue;
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("listener: bind_server");
            continue;
        }
        break;
    }
    if (p == NULL) {
        fprintf(stderr, "listener: failed to bind socket\n");
        exit(2);
    }
    struct sockaddr_in socket_addr;
    socklen_t length = sizeof(socket_addr);
    if(getsockname(sockfd, (struct sockaddr *)&socket_addr,&length) == -1){
        perror("error in getsocketname()");
        exit(-1);
    }
    port_number_proxy = (int)ntohs(socket_addr.sin_port);
    freeaddrinfo(servinfo);
    printf("listener: waiting to recvfrom...\n");
    return sockfd;
}

int client_connection(){
    int sockfd, sockfd_raw;
    struct addrinfo hints, *servinfo, *p, *clientinfo, *c;
    int rv, n;
    int numbytes;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // set to AF_INET to force IPv4
    hints.ai_socktype = SOCK_DGRAM;

    char port_number_proxy_char[10];
    sprintf(port_number_proxy_char,"%d",port_number_proxy);
    if ((rv = getaddrinfo("10.0.2.15", port_number_proxy_char, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo_server_in_client: %s\n", gai_strerror(rv));
        exit(1);
    }
    if ((rv = getaddrinfo("192.168.201.2", "0", &hints, &clientinfo)) != 0) {
        fprintf(stderr, "getaddrinfo_client: %s\n", gai_strerror(rv));
        exit(1);
    }
    for(c = clientinfo; c!= NULL; c = c->ai_next) {
        if ((sockfd = socket(c->ai_family, c->ai_socktype,
                c->ai_protocol)) == -1) {
            perror("talker: client socket");
            continue;
        }
        if (bind(sockfd, c->ai_addr, c->ai_addrlen) == -1) {
            close(sockfd);
            perror("listener: client bind");
            continue;
        }
        break;
    }

    for(c = clientinfo; c!= NULL; c = c->ai_next) {
        if ((sockfd_raw = socket(AF_INET, SOCK_RAW,
                IPPROTO_ICMP)) == -1) {
            perror("talker: raw socket");
            continue;
        }
        if (bind(sockfd_raw, c->ai_addr, c->ai_addrlen) == -1) {
            close(sockfd);
            perror("listener: raw bind");
            continue;
        }
        break;
    }

    if (c == NULL) {
        fprintf(stderr, "talker: client failed to create socket\n");
        exit(2);
    }
    p = servinfo;
    
    char child_pid[100];
    sprintf(child_pid,"%d", getpid());
    printf("length of pid=%lu & pid =%s\n",strlen(child_pid), child_pid);
    struct sockaddr_in socket_addr;
    socklen_t length = sizeof(socket_addr);
    if(getsockname(sockfd, (struct sockaddr *)&socket_addr,&length) == -1){
        perror("error in getsocketname()");
        exit(-1);
    }
    port_number_router = (int)ntohs(socket_addr.sin_port);

    sprintf(child_pid+strlen(child_pid),"a");
    sprintf(child_pid+strlen(child_pid),"%d", port_number_router);

    if ((numbytes = sendto(sockfd,child_pid,strlen(child_pid), 0,
         p->ai_addr, p->ai_addrlen)) == -1) {
        perror("talker_router: sendto");
        exit(1);
    }
    
    char buffer[2048];
    //struct sockaddr_storage their_addr_proxy;
    //socklen_t addr_len_proxy;
    //addr_len_proxy = sizeof their_addr_proxy;
    n = sockfd_raw +1;
    while(1){

        fd_set readfds;

        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);
        FD_SET(sockfd_raw, &readfds);

        rv = select(n, &readfds, NULL, NULL, NULL);

        if (rv == -1) {
            perror("select"); // error occurred in select()
        }

        else{
            // ICMP packet coming from proxy
            if (FD_ISSET(sockfd, &readfds)) {

                recv(sockfd, buffer, 84, 0);
                if(buffer[0] == '1'){
                    printf("Exiting router\n");
                    exit(0);
                } 
                struct iphdr *ip = (struct iphdr *)(buffer);
                struct icmphdr *icmp = (struct icmphdr *)(buffer+sizeof(struct iphdr));
                printf("!!!!! got a packet in router\n");
                char *some_addr;
                some_addr = inet_ntoa(*(struct in_addr*)&ip->daddr);
                // check for ip address & correspondingly send
                if(strcmp(some_addr, "192.168.201.2") == 0){
                    uint32_t temp;
                    temp = ip->saddr;
                    ip->saddr = ip->daddr;
                    ip->daddr = temp;

                    icmp->type =0;

                    if ((numbytes = sendto(sockfd,buffer,84, 0,
                            p->ai_addr, p->ai_addrlen)) == -1) {
                        perror("talker_router: sendto");
                        exit(1);
                    }
                }
                else{
                    // sendmsg format referred from http://www.microhowto.info/howto/send_an_arbitrary_ipv4_datagram_using_a_raw_socket_in_c.html
                    struct msghdr buf;
                    struct iovec iov[1];
                    iov[0].iov_base=&icmp;
                    iov[0].iov_len=8;
                    buf.msg_name=c->ai_addr;
                    buf.msg_namelen=c->ai_addrlen;
                    buf.msg_iov=iov;
                    buf.msg_iovlen=1;
                    buf.msg_control=0;
                    buf.msg_controllen=0;
                    printf("!!!!! Nooooooooooooooooooooooow sending packet raw\n");
                    if ((numbytes = sendmsg(sockfd_raw,&buf, 0)) == -1) {
                        perror("talker_router: sendto");
                        exit(1);
                    }
                } 
            }
            if (FD_ISSET(sockfd_raw, &readfds)) {
                recv(sockfd_raw, buffer, 84, 0);
                
                struct iphdr *ip = (struct iphdr *)(buffer);
                struct icmphdr *icmp = (struct icmphdr *)(buffer+sizeof(struct iphdr));
                printf("!!!!! recived packet raw ip source address %s\n",inet_ntoa(*(struct in_addr*)&ip->saddr));
                uint32_t temp;
                temp = ip->saddr;
                ip->saddr = ip->daddr;
                ip->daddr = temp;

                icmp->type =0;

                if ((numbytes = sendto(sockfd,buffer,84, 0,
                        p->ai_addr, p->ai_addrlen)) == -1) {
                    perror("talker_router: sendto");
                    exit(1);
                }
            }
        }  
    }
    freeaddrinfo(servinfo);
    close(sockfd);  
    exit(0);
}

int main(int argc, char** argv)
{

    read_file(argv[1]);

    sockfd_proxy = server_connection();

    if (fork() == 0){
        client_connection();
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
        printf("listener_PROXY: packet is %d bytes long\n", numbytes);
        buf[numbytes] = '\0';
        printf("listener_PROXY: packet contains \"%s\"\n", buf);

        /////////////////////////
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
        strncpy(port_number_router_char_global, port_number_router_char, strlen(port_number_router_char));

        if(stage == '1'){
            out_proxy = fopen("stage1.proxy.out","w+");
            fprintf(out_proxy,"proxy port: %d\nrouter:1, pid:%s, port:%s",port_number_proxy,pid_router_char, port_number_router_char);
            fclose(out_proxy);

            out_router = fopen("stage1.router1.out","w+");
            fprintf(out_router,"router:1, pid:%s, port:%s",pid_router_char, port_number_router_char);
            fclose(out_router);
        }

        else if (stage == '2'){
            printf("in stage 2");
            tunnel_reader();    
        }
    }
    close(sockfd_proxy);

    return 0;
}
