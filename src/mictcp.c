#include "../include/mictcp.h"
#include "../include/api/mictcp_core.h"
#include <api/thrd_timer.h>
#include <string.h>
#include <time.h>

#define MAX_SOCKET 100
#define TIMEOUT 100
#define MAX_REENVOI 20


mic_tcp_sock mysockets[MAX_SOCKET];
mic_tcp_sock_addr socket_to_addr_dest[MAX_SOCKET];
int last_index_socket=0;
int service_mode;



unsigned int PE=0,PA=0;



#define TAILLE_FENETRE 20 //taille de la fenetre mémoire 
#define PERTES_SIMULES 10//pertes simules par le gateway
#define PERTES_AUTORISEES 15 //pertes autorisées par défaut par la source
#define PERTES_POSSIBLE_RECV 15 // pertes autorisées par défaut par le puit

int fenetre[TAILLE_FENETRE];  //fenetre mémoire de packet perdus non reenvoyes (1) et des packets bien reçus (0) 



mic_tcp_sock mysockets[MAX_SOCKET];// tableau des sockets 
mic_tcp_sock_addr socket_to_addr_dest[MAX_SOCKET];  //tableau où l'on stocke les addreses destinatrices des sockets
int next_index_socket=0; //index du prochain socket utilisable
int erreur_fixe = PERTES_AUTORISEES ; //pourcentage de pertes que l'on authorise 


//variables globales utiles pour le bon fonctionnement des sous-fonctions 
//qui traitent la fenetre 
int pointeur_fenetre = 0;
int initialisee_fenetre=0;

//Sous fonctions de gestion de la fenêtre glissante

int count_ones()
{   
    int rep=0; 
    for(int i=0;i<pointeur_fenetre || (i<TAILLE_FENETRE && initialisee_fenetre) ;i++)
    {
        if (fenetre[i]==1)
        {rep++; }
    }
    return rep;
}

void stateToString(protocol_state state, char* res, int sizemax){
    if(res != NULL){
        switch(state){
            case IDLE:
            strncpy(res, "IDLE", sizemax);
            break;

            case CLOSED:
            strncpy(res, "CLOSED", sizemax);
            break;

            case WAIT_ACK_HANDSHAKE:
            strncpy(res, "WAIT_ACK_HANDSHAKE", sizemax);
            break;

            case WAIT_SYNACK_HANDSHAKE:
            strncpy(res, "WAIT_SYNACK_HANDSHAKE", sizemax);
            break;

            default:
            perror("No state corresponding : Unknow state ");
            exit(-1);
            break;
        
        }
    }
    
}

int pourcentage_erreur_fenetre()
{
   // if(pointeur_fenetre < TAILLE_FENETRE)
    return initialisee_fenetre?(count_ones()*100/TAILLE_FENETRE):(count_ones()*100/(pointeur_fenetre+1)); 
}

void add_fenetre(int value)
{
    if (pointeur_fenetre<TAILLE_FENETRE)
    {
        fenetre[pointeur_fenetre]=value;
    }
    else
    {
        if(!initialisee_fenetre)
        initialisee_fenetre=1;

        pointeur_fenetre=0;
        fenetre[pointeur_fenetre] = value;
    } 
     pointeur_fenetre++;
}
void affiche_fenetre()
{
    for (int i=0;i<pointeur_fenetre|| (i<TAILLE_FENETRE && initialisee_fenetre) ;i++)
    printf("%d ",fenetre[i]); 
    printf("\n");


}

/*
Cette fonction vérifie si le numéro de socket est dans les cas possibles
*/


int is_valid_sock_numb(int sock)
{
    return (sock >= 0 && sock < MAX_SOCKET);
}


/*
Cette fonction vérifie si le socket référencé à bien été initialisé
*/ 
int is_socket_used(int sock)
{
    return (sock < last_index_socket && is_valid_sock_numb(sock));  
}
/*
Retourne le numero de socket en fonction du numero de port
/!\ : La fonction ne vérifie pas si le socket est déjà en cours  
*/
int port_to_socket( int port )
{
	for(int i=0; i<MAX_SOCKET;i++)
	{
		if(mysockets[i].addr.port==port)
			return i;
	}
	return -1;
}



/*
 * Permet de créer un socket entre l’application et MIC-TCP
 * Retourne le descripteur du socket ou bien -1 en cas d'erreur
 */
int mic_tcp_socket(start_mode sm) 
{
    service_mode = sm;
   int result = -1;
   printf("[MIC-TCP] Appel de la fonction: ");  printf(__FUNCTION__); printf("\n");
   result = initialize_components(sm); /* Appel obligatoire */
   set_loss_rate(PERTES_SIMULES);
   
   if((result != -1) && is_valid_sock_numb(last_index_socket+1))
   {
        mysockets[last_index_socket].state = IDLE;
        mysockets[last_index_socket].fd=last_index_socket;
        last_index_socket++; 
   }
   else
   {
       perror("Erreur mictcp_socket ");
       return -1;
   }

    return mysockets[last_index_socket].fd;
}

/*
 * Permet d’attribuer une adresse à un socket. 
 * Retourne 0 si succès, et -1 en cas d’échec
 */

int mic_tcp_bind(int socket, mic_tcp_sock_addr addr)
{
   printf("[MIC-TCP] Appel de la fonction: ");  printf(__FUNCTION__); printf("\n");
   //on vérifie qu'on a déjà initialisé le socket
   if (is_socket_used(socket))
   { 
       if(addr.ip_addr!=NULL)
       {
            addr.ip_addr_size = strlen(addr.ip_addr);
            mysockets[socket].addr.ip_addr = malloc(addr.ip_addr_size);
            strcpy(mysockets[socket].addr.ip_addr, addr.ip_addr);
            mysockets[socket].addr.ip_addr_size = addr.ip_addr_size;
            mysockets[socket].addr.port = addr.port;
       }
       return 0;
   }
   else
   {
       perror("Bind error mauvais numéro de socket ");
       return -1;
   }
}


/*
 * Met le socket en état d'acceptation de connexions
 * Retourne 0 si succès, -1 si erreur
 */
int mic_tcp_accept(int socket, mic_tcp_sock_addr* addr)
{
    //version sans fiabilité
    printf("[MIC-TCP] Appel de la fonction: ");  printf(__FUNCTION__); printf("\n");
    
    if(is_socket_used(socket))
    {
        while( mysockets[socket].state != ESTABLISHED );

        return 0;
    }
    else
    {
        perror("Error accept() : Mauvais socket ");
        return -1;
    }
}

/*
 * Permet de réclamer l’établissement d’une connexion
 * Retourne 0 si la connexion est établie, et -1 en cas d’échec
 */
int mic_tcp_connect(int socket, mic_tcp_sock_addr addr)
{  
    //version sans fiabilité
    printf("[MIC-TCP] Appel de la fonction: ");  printf(__FUNCTION__); printf("\n");
    
    mic_tcp_pdu pdu_etab_conn;
	mic_tcp_sock_addr addr_dest;
    int result;
    int nb_envoi_conn_max = MAX_REENVOI;
    int seuil_max_pertes;

    printf("Bonjour\nVeuillez fixer un seuil de perte maximal (pourcentage ent 0 et 100)\n");
    char rep[5]; 
    fgets(rep,3,stdin);
    seuil_max_pertes=atoi(rep);
    if (seuil_max_pertes>=0 || seuil_max_pertes<=100)
    {NULL;}
    else 
    {seuil_max_pertes=PERTES_AUTORISEES;
    printf("Valeur par défaut proposée\n");}
    


    if(is_socket_used(socket))
    {

        //Stocke l'addresse distante pour l'envoie dans la fonction send ()
        socket_to_addr_dest[socket].ip_addr_size = strlen(addr.ip_addr)+1;
        socket_to_addr_dest[socket].ip_addr = malloc(socket_to_addr_dest[socket].ip_addr_size);
        socket_to_addr_dest[socket].port = addr.port;
        strcpy(socket_to_addr_dest[socket].ip_addr, addr.ip_addr); //strcpy car chaine caractere


        //addr_dest est remplir
        addr_dest = socket_to_addr_dest[socket];
        
        //Construction of SYN
            //ACK header
        pdu_etab_conn.header.dest_port=addr_dest.port;
        pdu_etab_conn.header.source_port=mysockets[socket].addr.port;
        pdu_etab_conn.header.syn = 1;
        pdu_etab_conn.header.ack = 0;
        pdu_etab_conn.header.fin = 0;
        pdu_etab_conn.header.seq_num = seuil_max_pertes;                                      //A REVOIR
            //ACK payload
        pdu_etab_conn.payload.data=NULL;
        pdu_etab_conn.payload.size=0;
        
        
        while( nb_envoi_conn_max > 0 )
        {
            //Envoie de SYN
            result=IP_send(pdu_etab_conn, addr_dest);
            if(result == -1)
            {
                perror("Echec envoie du pdu SYN lors de l'etablissement de conn. ");
                return -1;
            }

            printf("%d envoi de SYN pour etabliss; conn. ! \n ", MAX_REENVOI+1-nb_envoi_conn_max);
            mysockets[socket].state = WAIT_SYNACK_HANDSHAKE;

            //Attende de reception d'un SYN-ACK ou d'un TIMEOUT
            while( !thrd_timer(TIMEOUT) || mysockets[socket].state != RECEPTION_SYNACK_HANDSHAKE);


            if(mysockets[socket].state != RECEPTION_SYNACK_HANDSHAKE)
            {
                //TIMEOUT
                nb_envoi_conn_max--;
                printf("TIMEOUT \n");
            }
            else
            {
                //SYNACK RECU

                nb_envoi_conn_max = -1; // Pour sortir de la boucle

                printf("SYN-ACK recu durant etabliss. conn. ! \n");

                //Construction du ACK
                pdu_etab_conn.header.syn = 0;
                pdu_etab_conn.header.ack = 1;

                result = IP_send(pdu_etab_conn, addr_dest);
                if(result == -1)
                {
                    perror("Echec envoie du pdu ACK lors de l'etablissement de conn. ");
                    return -1;
                }

            
                printf("Envoi de ACK pour etabliss. conn.  { connect() }! \n ");

                // /!\ Dans le cas ou le ACK pourrait être perdu il faut :
                // Lancement d'un thread recuperateur de SYNACK
                //  Le thread renvoi l'ACK si il recoit un SYN-ACK
                //  Au bout d'un temps determine (relativement grand), 
                //  il envoit un signal d'arrêt au thread principal (celui qui envoie les données) 
                //  pour lui dire qu'il est inutile de continuer les envoies car l'établissement de connection a échoué
            }
             
            
            
        }
        
        if(nb_envoi_conn_max == 0)
        {
            perror("Nombre maximale de demande de connexion atteinte ");
            return -1;
        }

        mysockets[socket].state = ESTABLISHED;
        printf("On a choisit %d pourcent de pertes \n", erreur_fixe);

        return 0;
    }
    else 
    {
	    perror("Erreur connect : erreur socket ");
        return -1;
    }
}

/*
 * Permet de réclamer l’envoi d’une donnée applicative
 * Retourne la taille des données envoyées, et -1 en cas d'erreur
 */
int mic_tcp_send (int mic_sock, char* mesg, int mesg_size)
{
    printf("[MIC-TCP] Appel de la fonction: "); printf(__FUNCTION__); printf("\n");
    mic_tcp_pdu p;
	mic_tcp_sock_addr addr_dest;
    int nb_reprise=MAX_REENVOI;
    int result;

    if(is_socket_used(mic_sock))
    {        
        //Recuperer addresse du socket destinataire
        addr_dest = socket_to_addr_dest[mic_sock];

        //Payload
        p.payload.data = malloc(mesg_size);
        memcpy(p.payload.data, mesg, mesg_size);
        p.payload.size = mesg_size;

        //Header
        p.header.source_port = mysockets[mic_sock].addr.port;
        p.header.dest_port = addr_dest.port;
        p.header.seq_num = PE;
        p.header.ack_num = -1;
        p.header.syn = 0;
        p.header.ack = 0;
        p.header.fin = 0;
        PE= 1 - PE;
      
        
       while( nb_reprise>0 )
       {
            result=IP_send(p, addr_dest);
            printf("Tentative numero %d \n ", MAX_REENVOI +1 - nb_reprise);
            
            //Attente de reception d'un ACK ou d'un TIMEOUT
                // Gestion du numero de sequence dans process_received_pdu
            while( !thrd_timer(TIMEOUT) || mysockets[mic_sock].state != RECEPTION_ACK_DATA);
            
            if( mysockets[mic_sock].state != RECEPTION_ACK_DATA )
            {
                //TIMEOUT
                // On verifie si l'on peut tolerer cette eventuelle perte 
                if(pourcentage_erreur_fenetre() < erreur_fixe  )
                {
                    //On accepte la perte

                    printf("Perte acceptée \n");
                    nb_reprise = -1; // On sort
                    // On passe au packet suivant;
                    PE = 1 - PE;   
                    add_fenetre(1); 
                }
                else
                {
                    nb_reprise--;
                    printf("Renvoi \n");
                }
            }
            else
            {
                //On a recu l'ACK
                nb_reprise=-1;
                printf("ACK recu ! \n ");
                add_fenetre(0);
            }
       }    
       
        if(nb_reprise == 0) 
        {
            result = -1;
        }
        


        affiche_fenetre(); 
       printf("Pourcentage de pertes actuelles (sur 20 derniers pacquets) =%d Pourcentage d'erreur authorisé = %d\n",pourcentage_erreur_fenetre(),erreur_fixe);
        
        free(p.payload.data); // Liberation des ressources qu'on a malloc
        return result;
    }
    else
    {
        perror("Erreur mic_tcp_send() [Mauvais numero socket] ");
        return -1;
    }
    

}

/*
 * Permet à l’application réceptrice de réclamer la récupération d’une donnée 
 * stockée dans les buffers de réception du socket
 * Retourne le nombre d’octets lu ou bien -1 en cas d’erreur
 * NB : cette fonction fait appel à la fonction app_buffer_get() 
 */
int mic_tcp_recv (int socket, char* mesg, int max_mesg_size)
{
    printf("[MIC-TCP] Appel de la fonction: "); printf(__FUNCTION__); printf("\n");
    mic_tcp_pdu p; 
    int msg_size;
    if ( mysockets[socket].state==ESTABLISHED && is_socket_used(socket))
    {   

        p.payload.data=mesg;
        p.payload.size=max_mesg_size;
        msg_size=app_buffer_get(p.payload, 1);//Mode bloquant : la fonction bloque le thread jusqu'à ce qu'il ait au moins un pdu dans le buffer 
        return msg_size; 
    }
    else {
        perror(" TCP recv error");
        return -1; 
	}
}

/*
 * Permet de réclamer la destruction d’un socket. 
 * Engendre la fermeture de la connexion suivant le modèle de TCP. 
 * Retourne 0 si tout se passe bien et -1 en cas d'erreur
 */
int mic_tcp_close (int socket)
{   

    int nb_envoi_max=10; 
    printf("[MIC-TCP] Appel de la fonction :  "); printf(__FUNCTION__); printf("\n");
    int ret;
    int thread_listening = 1; //Avant la fermeture on sait que le thread est actif (on init pour eviter le warning)
    
    if(is_socket_used(socket))
    {
        mic_tcp_pdu fin; 
        fin.header.fin=1; 
        fin.header.syn=0; 
        fin.header.ack=0; 
        fin.payload.size=0; 
        fin.header.source_port = mysockets[socket].addr.port;
        fin.header.dest_port = socket_to_addr_dest[socket].port;

        while(nb_envoi_max>0)
        {
            if( -1 == IP_send(fin,socket_to_addr_dest[socket]) )
            {
                perror("Erreur mic_tcp_close() ");
                return -1;
            }

            // Attente reception de FINACK
            while( !thrd_timer(TIMEOUT) || mysockets[socket].state != RECEPTION_FINACK_HANDSHAKE);

            if( mysockets[socket].state == RECEPTION_FINACK_HANDSHAKE ) 
            {
                printf("PDU FIN ACK recu ! \n");
                nb_envoi_max = -1; // On sort de la boucle
            }
            else
            {
                nb_envoi_max--;
            }
   
         }

        if ( nb_envoi_max==0 )
        {
            printf ("Nombre de tentatives dépassés, je me ferme\n");
        }

        thread_listening = 1 - thread_listening; // On bascule sur l'état 0. Le thread termine.
        mysockets[socket].state=CLOSED;
        free(socket_to_addr_dest[socket].ip_addr);
        free(mysockets[socket].addr.ip_addr);

        ret = 0;
    }
    else
    {
        perror("mic_tcp_close");
        ret = -1;
    }

    return ret;
}

/*
 * Traitement d’un PDU MIC-TCP reçu (mise à jour des numéros de séquence
 * et d'acquittement, etc.) puis insère les données utiles du PDU dans 
 * le buffer de réception du socket. Cette fonction utilise la fonction 
 * app_buffer_put().   
 */
void process_received_PDU(mic_tcp_pdu pdu, mic_tcp_sock_addr addr )
{
    printf("[MIC-TCP] Appel de la fonction: "); printf(__FUNCTION__); printf("\n");
    int mysocket_numb;
    mic_tcp_pdu ack;
    mic_tcp_pdu fin_ack;
    mic_tcp_pdu pdu_etab_conn;

    mysocket_numb = port_to_socket(pdu.header.dest_port) ;
    
    //SERVER
    if( service_mode == SERVER )
    {
        if(mysocket_numb != -1 && is_socket_used(mysocket_numb)){

            protocol_state currentState = mysockets[mysocket_numb].state;
            
            if( currentState == ESTABLISHED &&pdu.header.fin==0)
            {   
                
                ack.header.ack = 1;
                ack.header.syn = 0;
                ack.header.fin = 0;

                ack.header.dest_port = addr.port;
                //ack.header.dest_port = pdu.header.source_port;

                //ack.header.source_port = mysockets[0].addr.port;
                ack.header.source_port = pdu.header.dest_port;
                ack.payload.size = 0;
                ack.payload.data = NULL;

                if( pdu.header.seq_num == PA && pdu.payload.size > 0 )
                {
                    printf("PDU recu numero de sequence OK ! \n ");
                    PA = (PA+1)%2;
                    app_buffer_put(pdu.payload);
                }
                else
                {
                    printf("PDU recu seq num NON OK ! \n ");
                }

                ack.header.ack_num = PA;
                printf("J'ai recu de { IP %s | Port %d | Taille %d } \n", addr.ip_addr, addr.port, addr.ip_addr_size);
                    
                if( IP_send(ack, addr) == -1 )
                {
                    perror("Erreur dans IP_send ");
                    exit(-1);
                }

                if( pdu.header.seq_num == PA && pdu.payload.size > 0 )
                {
                    app_buffer_put(pdu.payload);
                }

            }
            else if(currentState==ESTABLISHED &&  pdu.payload.size == 0 && pdu.header.fin == 1 )//PDU=FIN
                    { 
                        fin_ack.payload.data = NULL;
                        fin_ack.payload.size = 0; 
                        fin_ack.header.ack = 1;
                        fin_ack.header.syn = 0;
                        fin_ack.header.fin = 1;

                        if( IP_send(fin_ack, addr) == -1 )
                            {
                                perror("Erreur dans IP_send ");
                                exit(-1);
                            }
                            else
                            {   
                                printf("J'ai recu de { IP %s | Port %d | Taille %d } \n", addr.ip_addr, addr.port, addr.ip_addr_size);
                                printf("PDU de fin  de connection reçu \n");
                                free(mysockets[mysocket_numb].addr.ip_addr);
                                free(socket_to_addr_dest[mysocket_numb].ip_addr);
                                mysockets[mysocket_numb].state=CLOSED;
                                exit(1);

                        
                        }
                            
                    }

                
            
            else if( currentState == IDLE || currentState == WAIT_ACK_HANDSHAKE )
            {
            if( pdu.payload.size == 0 && pdu.header.fin == 0 )
                {
                    if( pdu.header.syn && pdu.header.ack == 0 )//pdu = SYN
                    {   
                        printf("pdu SYN recu ! \n");

                        //Construction du SYN-ACK
                        pdu_etab_conn.header.ack = 1;
                        pdu_etab_conn.header.syn = 1;
                        pdu_etab_conn.header.fin = 0;

                        if(pdu.header.seq_num >= 0 && pdu.header.seq_num <= 100) //TEST de NEGOCIATION
                        {

                            pdu_etab_conn.header.seq_num = pdu.header.seq_num < PERTES_POSSIBLE_RECV ?  pdu.header.seq_num :  PERTES_POSSIBLE_RECV;
                            
                            pdu_etab_conn.payload.data = NULL;
                            pdu_etab_conn.payload.size = 0;

                            if( IP_send(pdu_etab_conn, addr) == -1 )
                            {
                                perror("Erreur dans IP_send ");
                                exit(-1);
                            }
                            mysockets[mysocket_numb].state = WAIT_ACK_HANDSHAKE;
                        }
                    }
                    else if( pdu.header.ack ) // pdu == ACK
                    {
                        printf("pdu ACK recu ! \n");
                        
                        socket_to_addr_dest[mysocket_numb] = addr;
                        socket_to_addr_dest[mysocket_numb].ip_addr = malloc(addr.ip_addr_size);
                        strcpy(socket_to_addr_dest[mysocket_numb].ip_addr, addr.ip_addr);
                        mysockets[mysocket_numb].state = ESTABLISHED;
                        
                    }
                    
                }
                


            }
        
            else
            {
                printf("Erreur process_received_pdu : Mauvais etat \n");
            }
            
        
        }
    }
    else
    {
        //CLIENT
        //printf("Hello \n");
        if( mysockets[mysocket_numb].state == WAIT_SYNACK_HANDSHAKE )
        {
            //Verification pdu est bien un SYN-ACK
            if( pdu.payload.size == 0 && pdu.header.syn && pdu.header.ack )
            {    
                printf("PDU SYNACK reçu \n");
                //passer l'etat à RECEPTION_SYNACK_HANDSHAKE
                mysockets[mysocket_numb].state = RECEPTION_SYNACK_HANDSHAKE;
            }
                
        }
        else if (mysockets[mysocket_numb].state == WAIT_SYNACK_HANDSHAKE)
        {
            //Verification pdu est bien un SYN-ACK
            if( pdu.payload.size == 0 && pdu.header.syn == 0 && pdu.header.ack )
            {   
                if( pdu.header.ack_num == PE) 
                { 
                   //passer l'etat à RECEPTION_SYNACK_HANDSHAKE
                    mysockets[mysocket_numb].state = RECEPTION_ACK_DATA;
                }
                else
                {
                    printf("Reception ACK avec mauvais numero de sequence -> rejet ! \n");
                }
                
            }

        }
        else if (pdu.payload.size == 0 && pdu.header.fin && pdu.header.ack)
        {
            
            mysockets[mysocket_numb].state = RECEPTION_FINACK_HANDSHAKE;
        }
        
    }
    

}