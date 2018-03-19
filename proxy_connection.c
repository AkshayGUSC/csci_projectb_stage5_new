#include "main_header.h"

int server_connection(){
    /*Socket connection code copied from BEEJ TUTORIAL*/
    int sockfd;
    struct sockaddr_in proxy_addr;
    
    if ((sockfd = socket(AF_INET, SOCK_DGRAM,0)) == -1) {
        perror("talker: raw socket");
    }

    memset(&proxy_addr, 0x00, sizeof(struct sockaddr_in));    
    proxy_addr.sin_addr.s_addr = inet_addr("10.0.2.15");
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(0);
    if (bind(sockfd, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr)) == -1) {
        close(sockfd);
        perror("listener: raw bind");
    }
    
    struct sockaddr_in socket_addr;
    socklen_t length = sizeof(socket_addr);
    if(getsockname(sockfd, (struct sockaddr *)&socket_addr,&length) == -1){
        perror("error in getsocketname()");
        exit(-1);
    }
    port_number_proxy = (int)ntohs(socket_addr.sin_port);

    out_proxy = fopen("stage4.proxy.out","w+");
    fprintf(out_proxy,"proxy port: %d\n",port_number_proxy);
    fflush(NULL);
    return sockfd;
}