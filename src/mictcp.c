#include "../include/mictcp.h"
#include "../include/api/mictcp_core.h"
#include <string.h>
#include <time.h>

#define TIMEOUT 10000 //millisec
#define MAX_CONN_SENDING 10


int default_port = 8751;
mic_tcp_sock_addr socket_to_addr_dest[MAX_SOCKET];
int last_index_socket=0;
int service_mode;

unsigned int PE=0,PA=0;

#define SIMULATED_LOSS 10//Loss effectively simulated by the gateway
#define MAX_AUTH_LOSS 15 //Maximal loss authorised by PRTCP

mic_tcp_sock mysockets[MAX_SOCKET];// tableau des sockets
int next_index_socket=0; //index du prochain socket utilisable
int erreur_fixe = MAX_AUTH_LOSS ; //pourcentage de pertes que l'on authorise

/*
    WINDOW variables
*/

int seq_num_first_elmnt=0;

//variables globales utiles pour le bon fonctionnement des sous-fonctions
//qui traitent la fenetre
int pointeur_fenetre = 0;
int initialisee_fenetre=0;

/*
    Function packets
*/

void printPW(){
    for(int i=0; i<WINDOW_SIZE; i++)
    {
        printf(" { <%p>", packet_window[i]);
        if(packet_window[i] != NULL){
            printf("(%d) } %d\n", packet_window[i]->header.seq_num, i);
        }
        else
        {
            printf(" } %d\n", i);
        }
    }
    printf(" \n");
}

void free_packet(mic_tcp_pdu* p){
    free(p->payload.data);
    free(p);
}

/*
Cette fonction vérifie si le numéro de socket est coherent
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
   set_loss_rate(SIMULATED_LOSS);

   if((result != -1) && is_valid_sock_numb(last_index_socket+1))
   {
        mysockets[last_index_socket].state = IDLE;
        mysockets[last_index_socket].fd=last_index_socket;
        mysockets[last_index_socket].addr.port = default_port++;
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
       }
        mysockets[socket].addr.port = addr.port; // Default port is replaced by the one chosen (binding)
        char* service;
        service = service_mode == CLIENT ? "CLIENT" : "SERVER"; 
        printf(" [%s] Port %d \n", service, mysockets[socket].addr.port);
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
    printf("[ State ]"); printfState(mysockets[socket].state);printf("\n");

        while( mysockets[socket].state != ESTABLISHED );

    printf("[ State ]"); printfState(mysockets[socket].state);printf("\n");

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
    int nb_envoi_conn_max = MAX_CONN_SENDING;
    int seuil_max_pertes = MAX_AUTH_LOSS;
    int timeout_synack_cond = 1, timeout, synack;



    if(is_socket_used(socket))
    {
    printf("[ State ]"); printfState(mysockets[socket].state);printf("\n");

        //Stocke l'addresse distante pour l'envoie dans la fonction send ()
        socket_to_addr_dest[socket].ip_addr_size = strlen(addr.ip_addr)+1;
        socket_to_addr_dest[socket].ip_addr = malloc(socket_to_addr_dest[socket].ip_addr_size);
        socket_to_addr_dest[socket].port = addr.port;
        strcpy(socket_to_addr_dest[socket].ip_addr, addr.ip_addr); //strcpy car chaine caractere


        //addr_dest est remplir
        addr_dest = socket_to_addr_dest[socket];
        timerBox.destination_addr = socket_to_addr_dest + socket;


        //Construction of SYN
            // header
        pdu_etab_conn.header.dest_port=addr_dest.port;
        pdu_etab_conn.header.source_port=mysockets[socket].addr.port;
        pdu_etab_conn.header.syn = 1;
        pdu_etab_conn.header.ack = 0;
        pdu_etab_conn.header.fin = 0;
        pdu_etab_conn.header.ack_num = 0;
        pdu_etab_conn.header.seq_num = seuil_max_pertes;                                      //A REVOIR
            // payload
        pdu_etab_conn.payload.data=NULL;
        pdu_etab_conn.payload.size=0;


        while( nb_envoi_conn_max > 0 )
        {
/* ** CS ** */pthread_mutex_lock(&connect_mutex);

            //Envoie de SYN
            result=IP_send(pdu_etab_conn, addr_dest);
            printf("Envoi %d de SYN pour etab. conn. ! \n ", MAX_CONN_SENDING+1-nb_envoi_conn_max);
            if(result == -1)
            {
                perror("Echec envoie du pdu SYN lors de l'etab. de conn. ");
                return -1;
            }
            launch_HS_timer(TIMEOUT);

            mysockets[socket].state = WAIT_SYNACK_HANDSHAKE; 

/* ** CS ** */pthread_mutex_unlock(&connect_mutex);
            // This is a critical section (CS) because this sequence leads to an infinite loop :
            // Either th1 (this thread) and th2 those of process_received_pdu
            // 
            // th1 --> IP_send(...); printf(...); ... ; launch_HS_timer(...);
            // th2 --> Reception of the ACK; Validation of the tests; And... changement of the state in RECPETION... (what we are waiting for below)
            // th1 --> changement of the state to WAIT... and while(...) (which will end up with a timeout)
            //
            // Then by repeating this sequence we are trapped into this
            // So we need to ensure that the changement of the state into WAIT_SYNACK_HANDSHAKE is done right after the sending
            //
            // An another solution would be simply to remove the state WAIT_SYNACK_HANDSHAKE. But we would still need a mutex to enture that we launch the timer right after the sending


            // Waiting for the reception of a SYNACK or a TIMEOUT
            //int state_n, state_n1=0, t=0;
            while( timeout_synack_cond )
            {
                timeout = check_HS_timer(); // 0 if timeout happen 
                pthread_mutex_lock(&connect_mutex);
                synack = mysockets[socket].state != RECEPTION_SYNACK_HANDSHAKE; // 0 if we receive the ack
                pthread_mutex_unlock(&connect_mutex);
                timeout_synack_cond = timeout && synack;
            }

            if(mysockets[socket].state != RECEPTION_SYNACK_HANDSHAKE)
            {
                //TIMEOUT
                nb_envoi_conn_max--;
                printf("TIMEOUT \n");
            }
            else
            {
                //SYNACK RECU
                stop_HS_timer();
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


                printf("Envoi de ACK pour etabliss. conn.  [connect()] \n ");

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
            printf("Nombre maximale de demande de connexion atteinte \n");
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
    mic_tcp_pdu* p;
	mic_tcp_sock_addr addr_dest;
    int result;

    if(is_socket_used(mic_sock))
    {
        printf("[ State ]"); printfState(mysockets[mic_sock].state);printf("\n");

        //Recuperer addresse du socket destinataire
        addr_dest = socket_to_addr_dest[mic_sock];


        p = malloc(sizeof(mic_tcp_pdu));// For bufferisation

        //Payload
        p->payload.data = malloc(mesg_size); // For bufferisation
        memcpy(p->payload.data, mesg, mesg_size);
        p->payload.size = mesg_size;

        //Header
        p->header.source_port = mysockets[mic_sock].addr.port;
        p->header.dest_port = addr_dest.port;
        p->header.seq_num = PE;
        p->header.ack_num = 0;
        p->header.syn = 0;
        p->header.ack = 0;
        p->header.fin = 0;


        pthread_mutex_lock(&ew_state_mutex);

        while ( window_closed ){
            printf("WINDOW CLOSED ! We are waiting \n");
            pthread_cond_wait(&ew_state_cond, &ew_state_mutex);
        }

       // printf("WINDOW OPENED ! We go \n");

        // Here, the window is open and we hold the mutex

        int index_in_window = PE%WINDOW_SIZE;

        //Send
        result=IP_send(*p, addr_dest);

        //Bufferisation
        packet_window[index_in_window] = p;
        printf("pdu sent is stored at index %d \n", index_in_window);

        printPW();

        //Launching of the timer
        launch_timer(index_in_window, TIMEOUT);

        //update_counter_window(index_in_window);

        //PE=(PE+1)%WINDOW_SIZE;
        PE++;

        if( PE%WINDOW_SIZE == index_first_elmnt){
            window_closed = 1;
        }

        pthread_mutex_unlock(&ew_state_mutex);

    printf("Send finished !\n");
      return result;
    }

    printf("Bad socket descriptor [mictcp_send] \n");
    return -1;

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
    printf("[ State ]"); printfState(mysockets[socket].state);printf("\n");

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

    int nb_envoi_conn_max=MAX_CONN_SENDING;
    int timeout_finack_cond = 1, timeout, finack;

    printf("[MIC-TCP] Appel de la fonction :  "); printf(__FUNCTION__); printf("\n");

    
    if(is_socket_used(socket))
    {
        mysockets[socket].state = CLOSING;
        printf("[ State ]"); printfState(mysockets[socket].state);printf("\n");
        mic_tcp_pdu pdu_closing_conn;
        pdu_closing_conn.header.fin=1;
        pdu_closing_conn.header.syn=0;
        pdu_closing_conn.header.ack=0;
        pdu_closing_conn.payload.size=0;
        pdu_closing_conn.payload.data = NULL;
        pdu_closing_conn.header.source_port = mysockets[socket].addr.port;
        pdu_closing_conn.header.dest_port = socket_to_addr_dest[socket].port;

        while(nb_envoi_conn_max>0)
        {
            pthread_mutex_lock(&connect_mutex);
            if( -1 == IP_send(pdu_closing_conn,socket_to_addr_dest[socket]) )
            {
                perror("Error mic_tcp_close() ");
                return -1;
            }
            printf("Envoi %d de FIN pour etab. conn. ! \n ", MAX_CONN_SENDING+1-nb_envoi_conn_max);
            
            launch_HS_timer(TIMEOUT);
            pthread_mutex_unlock(&connect_mutex);

            // Waiting for FINACK reception
            while( timeout_finack_cond )
            {
                timeout = check_HS_timer(); // 0 if timeout happen 
                pthread_mutex_lock(&connect_mutex);
                finack = mysockets[socket].state != CLOSED; // 0 if we receive the ack
                pthread_mutex_unlock(&connect_mutex);
                timeout_finack_cond = timeout && finack;
            }

            if( mysockets[socket].state == CLOSED )
            {
                stop_HS_timer();

                printf("PDU FIN ACK recu [Timer shutdown] ! \n");
                printf("[ State ]"); printfState(mysockets[socket].state);printf("\n");

                /*if( -1 == IP_send(pdu_closing_conn,socket_to_addr_dest[socket]) )
                {
                    perror("Error mic_tcp_close() ");
                    return -1;
                }
                printf("ACK envoyé ! \n");*/

                nb_envoi_conn_max = -1; // On sort de la boucle
            }
            else
            {
                nb_envoi_conn_max--;
            }

         }

        if ( nb_envoi_conn_max==0 )
        {
            printf ("Nombre de tentatives dépassés, je me ferme\n");
        }

        thread_listening = 0; // We jump on the 0 state. The thread ends.
        mysockets[socket].state=IDLE;
        free(socket_to_addr_dest[socket].ip_addr);
        free(mysockets[socket].addr.ip_addr);
        printf("[ State ]"); printfState(mysockets[socket].state);printf("\n");
        return 0;
    }
    else
    {
        perror("mic_tcp_close");
        return -1;
    }
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

    //mysocket_numb = port_to_socket(pdu.header.dest_port) ;  PROBLEM DUE TOO PROBABLY GATEWAY
    mysocket_numb = 0;

    if(mysocket_numb == -1){
        printf("Error socket descriptor : port_to_socket failed \n");
    }

    if(mysocket_numb != -1 && is_socket_used(mysocket_numb))
    {
        //SERVER
        if( service_mode == SERVER )
        {
            protocol_state currentState = mysockets[mysocket_numb].state;

            if(currentState == ESTABLISHED)
            {
                if( pdu.payload.size > 0 )
                {
                    int index_window = pdu.header.seq_num % WINDOW_SIZE;
                    printf("[Client] PDU DATA recu numero de sequence (pdu.header.seq_num) %d ! \n ", pdu.header.seq_num);
                    printf("seq_num_first_elmnt %d \n", seq_num_first_elmnt);
                    printf("index_first_elmnt %d \n", index_first_elmnt);
                    printf("PA %d \n", PA);



                    if( pdu.header.seq_num == PA ) // The PDU we were waiting for...
                    {
                        // ACK
                        ack.header.ack = 1;
                        ack.header.syn = 0;
                        ack.header.fin = 0;
                        ack.header.dest_port = addr.port;// <=> ack.header.dest_port = pdu.header.source_port;
                        ack.header.source_port = pdu.header.dest_port;// <=> ack.header.source_port = mysockets[mysocket_numb].addr.port;
                        ack.payload.size = 0;
                        ack.payload.data = NULL;

                        app_buffer_put(pdu.payload);
                        PA++;
                        seq_num_first_elmnt++;
                        index_first_elmnt = (index_first_elmnt+1)%WINDOW_SIZE;

                        int shift=0;
 
                        while(packet_window[index_first_elmnt] != NULL)
                        {
                            app_buffer_put(packet_window[index_first_elmnt]->payload);
                            free_packet(packet_window[index_first_elmnt]);
                            packet_window[index_first_elmnt] = NULL;
                            shift++;
                            index_first_elmnt = (index_first_elmnt+1)%WINDOW_SIZE;
                        }
           

                        PA += shift;
                        seq_num_first_elmnt += shift;
                        ack.header.ack_num = PA;

                        if( IP_send(ack, addr) == -1 )
                        {
                            perror("Erreur dans IP_send ");
                        }

                    }
                    else // Hoho something wrong probably happen...
                    {
                        
                        printf("Hoho smthg went wrong [ packet lost ] \n");

                        if( pdu.header.seq_num >= seq_num_first_elmnt && pdu.header.seq_num < seq_num_first_elmnt + WINDOW_SIZE )
                        {
                            // Partial Reliability need to be considere here
                            if(packet_window[index_window] == NULL)
                            {
                                printf("Packet %d stored at index %d \n", pdu.header.seq_num ,index_window);
                                int size = sizeof(pdu);
                                packet_window[index_window] = malloc(size);
                                memcpy(packet_window[index_window], &pdu, size);
                                packet_window[index_window]->payload.data = malloc(pdu.payload.size);
                                memcpy(packet_window[index_window]->payload.data, pdu.payload.data, pdu.payload.size);

                            }
                            else
                            {
                                // ACK
                                ack.header.ack = 1;
                                ack.header.syn = 0;
                                ack.header.fin = 0;
                                ack.header.dest_port = addr.port;// <=> ack.header.dest_port = pdu.header.source_port;
                                ack.header.source_port = pdu.header.dest_port;// <=> ack.header.source_port = mysockets[mysocket_numb].addr.port;
                                ack.payload.size = 0;
                                ack.payload.data = NULL;
                                ack.header.ack_num = seq_num_first_elmnt;
                                if( IP_send(ack, addr) == -1 )
                                {
                                    perror("Erreur dans IP_send ");
                                }
                            }


                        }
                        else
                        { 
                            printf("Error seq_num \n");
                        }

                    }
                }
                else if( pdu.header.fin == 1 )//PDU=FIN
                {
                    fin_ack.payload.data = NULL;
                    fin_ack.payload.size = 0;
                    fin_ack.header.dest_port = addr.port;
                    fin_ack.header.source_port = mysockets[mysocket_numb].addr.port;
                    fin_ack.header.ack = 1;
                    fin_ack.header.syn = 0;
                    fin_ack.header.fin = 1;

                    if( IP_send(fin_ack, addr) == -1 )
                    {
                        perror("Error IP_send ");
                        exit(-1);
                    }

                    printf("FIN pdu received FIN-ACK sent ! \n");
                    free(mysockets[mysocket_numb].addr.ip_addr);
                    free(socket_to_addr_dest[mysocket_numb].ip_addr);
                    pthread_mutex_lock(&connect_mutex);
                    mysockets[mysocket_numb].state=CLOSING;
                    pthread_mutex_unlock(&connect_mutex);

                }

            }
            else //if( currentState == IDLE || currentState == WAIT_ACK_HANDSHAKE || currentState == CLOSING )
            {
                if( pdu.payload.size == 0 )
                {
                    if( pdu.header.syn && pdu.header.ack == 0 )//pdu = SYN
                    {
                        printf("pdu SYN recu ! \n");

                        //Construction du SYN-ACK
                        pdu_etab_conn.header.ack = 1;
                        pdu_etab_conn.header.syn = 1;
                        pdu_etab_conn.header.fin = 0;
                        pdu_etab_conn.header.source_port = pdu.header.dest_port;
                        pdu_etab_conn.header.dest_port = pdu.header.source_port;
                        pdu_etab_conn.header.ack_num = 0;
                        pdu_etab_conn.payload.size = 0;
                        pdu_etab_conn.payload.data = NULL;


                        if(pdu.header.seq_num >= 0 && pdu.header.seq_num <= 100) //NEGOCIATION TEST
                        {
                            pdu_etab_conn.header.seq_num = pdu.header.seq_num < 10 ?  pdu.header.seq_num : 10;
                            printf("pdu SYN-ACK sent \n");
                            if( IP_send(pdu_etab_conn, addr) == -1 )
                            {
                                perror("Error IP_send ");
                                exit(-1);
                            }
                            pthread_mutex_lock(&connect_mutex);
                            mysockets[mysocket_numb].state = WAIT_ACK_HANDSHAKE;
                            pthread_mutex_unlock(&connect_mutex);

                            // printf("[ State ]"); printfState(mysockets[mysocket_numb].state);printf("\n");
                        }
                    }
                    else if( pdu.header.ack ) // pdu == ACK
                    {
                        printf("pdu ACK recu ! \n");

                        if( currentState != CLOSING)
                        {
                            socket_to_addr_dest[mysocket_numb] = addr;
                            socket_to_addr_dest[mysocket_numb].ip_addr = malloc(addr.ip_addr_size);
                            strcpy(socket_to_addr_dest[mysocket_numb].ip_addr, addr.ip_addr);
                            pthread_mutex_lock(&connect_mutex);
                            mysockets[mysocket_numb].state = ESTABLISHED;
                            pthread_mutex_unlock(&connect_mutex);

                        }
                        else
                        {
                            pthread_mutex_lock(&connect_mutex);
                            //mysockets[mysocket_numb].state = CLOSED;
                            mysockets[mysocket_numb].state = IDLE;
                            pthread_mutex_unlock(&connect_mutex);
                            printf("[ State ]"); printfState(mysockets[mysocket_numb].state);printf("\n");        
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

            if( pdu.payload.size == 0 && pdu.header.ack)
            {
                //SYN-ACK Reception
                if( pdu.header.syn )
                {
                    printf("PDU SYNACK reçu \n");
                    pthread_mutex_lock(&connect_mutex);
                    mysockets[mysocket_numb].state = RECEPTION_SYNACK_HANDSHAKE;
                    pthread_mutex_unlock(&connect_mutex);
                }
                //FIN-ACK Reception
                else if( pdu.header.fin )
                {
                    printf("FINACK recu ! \n");

                    // ACK construction
                    pdu_etab_conn.header.ack = 1;
                    pdu_etab_conn.header.syn = 0;
                    pdu_etab_conn.header.fin = 0;
                    pdu_etab_conn.header.source_port = pdu.header.dest_port;
                    pdu_etab_conn.header.dest_port = pdu.header.source_port;
                    pdu_etab_conn.header.ack_num = 0;
                    pdu_etab_conn.payload.size = 0;
                    pdu_etab_conn.payload.data = NULL;

                    printf("ACK sent ! \n");
                    if( IP_send(pdu_etab_conn, addr) == -1 )
                    {
                        perror("Error IP_send ");
                        exit(-1);
                    }

                    pthread_mutex_lock(&connect_mutex);
                    mysockets[mysocket_numb].state = CLOSED;
                    pthread_mutex_unlock(&connect_mutex);

                }
                //ACK reception
                else
                {
                    //pthread_mutex_lock(&ew_state_mutex); // PE is seq numb of the next packet to send
                    // In the case where PE would be changed after this test, we will not consider the new packet that has been added what is not dramatic since we will process it next time
                    printf("ACK recu [BEFORE] \n");

                    pthread_mutex_lock(&ew_state_mutex);
                    printPW();
                    printf("pdu.header.acknum %d \n", pdu.header.ack_num);
                    printf("index_first_elmnt %d \n", index_first_elmnt);
                    printf("seq_num_first_elmnt %d \n", seq_num_first_elmnt);
                    printf("PE %d \n", PE);
                    if( pdu.header.ack_num > seq_num_first_elmnt && pdu.header.ack_num <= /*or < //!? */ PE)
                    {
                        int i=index_first_elmnt, ack_num_index = pdu.header.ack_num%WINDOW_SIZE;
                        int shift=0;
                        while(i != ack_num_index)
                        {
                            //Disabling of timers
                            stop_timer(i);
                            //Freeing in the packet window
                            free_packet(packet_window[i]);
                            packet_window[i] = NULL;

                            i = (i+1)%WINDOW_SIZE;
                            shift++;
                        }

                        //Shifting of the packet window
                        index_first_elmnt = ack_num_index; /* = pdu.header.ack_num%WINDOW_SIZE (but cost less since the variable <i> have always been passed throught the modulo) */
                        // Update of the seq num
                        seq_num_first_elmnt += shift;

                        //Notify that window is open
                        window_closed = 0;
                        pthread_cond_signal(&ew_state_cond);
                        
                        printPW();
                    }
                    else
                    {
                        //printf(" ")
                        printf("Reception ACK avec mauvais numero de sequence -> rejet ! \n");
                    }
                    pthread_mutex_unlock(&ew_state_mutex);
                }

            }

        }

    }else
    {
        perror("Error socket process_received_pdu ");
    }


}
