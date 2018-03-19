#include "sub_header.h"
#include "main_header.h"

int port_number_proxy;
int port_number_router;
int sockfd_proxy;
int port_number_router_int_global[6] ={0};
uint32_t address_list_global[6] ={0};
//FILE *out_proxy, *out_router;
char n_router;
char pid_router_char[100];    
int number_routers;
char stage;
int manitor_hops =0;

int read_file(char *path){

    FILE *fp = fopen(path, "r");
    char buf[100];
    while(!feof(fp)){
        fgets(buf, 100, fp);
        if(buf[0]!='#'){
            if(buf[0] == 's'){
                for(int i=5; i<100;i++){
                    if(buf[i]!=' ' && buf[i]!='\t' && buf[i]!='\n'){
                        stage = buf[i];
                        printf("Stage = %c\n",stage);
                        break;
                    }
                }   
            }
            else if (buf[0] == 'n'){
                for(int i=11; i<100;i++){
                    if((int)buf[i]>=48 && (int)buf[i]<=57){
                        n_router = buf[i];
                        break;
                    }
                }
                printf("No. of routers = %c\n", n_router);
            }
            else{
                for(int i=12; i<100;i++){
                    if((int)buf[i]>=48 && (int)buf[i]<=57){
                        manitor_hops = buf[i];
                        break;
                    }
                }
            }   
        }
        memset(buf, 0, 100);
    }
    fclose(fp);
    printf("No. of manitor_hops = %c\n", manitor_hops);

    return (n_router-48);
}
