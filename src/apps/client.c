#include <mictcp.h>
#include <stdio.h>
#include <string.h>

#define MAX_SIZE 1000

int main()
{

    int sockfd = 0;
    int NB_MAX_PDU = 100;
    char str[MAX_SIZE];
    mic_tcp_sock_addr addr;
    addr.ip_addr = "127.0.0.1";
    addr.port = 1234;
    addr.ip_addr_size = strlen(addr.ip_addr)+1;
    

    if ((sockfd = mic_tcp_socket(CLIENT)) == -1)
    {
        printf("[TSOCK] Erreur a la creation du socket MICTCP!\n");
        return 1;
    }
    else
    {
        printf("[TSOCK] Creation du socket MICTCP: OK\n");
    }

    if (mic_tcp_connect(sockfd, addr) == -1)
    {
        printf("[TSOCK] Erreur a la connexion du socket MICTCP!\n");
        return 1;
    }
    else
    {
        printf("[TSOCK] Connexion du socket MICTCP: OK\n");
    }

    memset(str, 0, MAX_SIZE);

    printf("[TSOCK] Entrez vos message a envoyer, CTRL+D pour quitter\n");
    for(int i=0; i<NB_MAX_PDU; i++)
    {
        snprintf(str, MAX_SIZE, "%d", i);
        int sent_size = mic_tcp_send(sockfd, str, strlen(str)+1);
        printf("[TSOCK] Appel de mic_send message { %s } : taille %lu\n", str, strlen(str)+1);
        printf("[TSOCK] Appel de mic_send valeur de retour : %d\n", sent_size);
    }

    mic_tcp_close(sockfd);

    return 0;
}
