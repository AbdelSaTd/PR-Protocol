#include <api/mictcp_core.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <math.h>
#include <time.h>
#include <pthread.h>
#include <strings.h>

/*****************
 * API Variables *
 *****************/
int initialized = -1;
int sys_socket;
pthread_t listen_th;
pthread_mutex_t lock;
unsigned short loss_rate = 0;
struct sockaddr_in remote_addr;


/* This is for the buffer */
TAILQ_HEAD(tailhead, app_buffer_entry) app_buffer_head;
struct tailhead *headp;
struct app_buffer_entry {
     mic_tcp_payload bf;
     TAILQ_ENTRY(app_buffer_entry) entries;
};

/* Condition variable used for passive wait when buffer is empty */
pthread_cond_t buffer_empty_cond;
pthread_cond_t connect_cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t connect_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t timeout_cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t timeout_mutex = PTHREAD_MUTEX_INITIALIZER;





pthread_t retransmission_tid;


/*
    WINDOW & TIMER variables
*/

pthread_cond_t ew_state_cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t ew_state_mutex = PTHREAD_MUTEX_INITIALIZER;

int timeout_th = 0;// Init to 0
//extern int counter_window[WINDOW_SIZE]; // 0 = lost packet; 1 = well-sent packet (received by the server)
int thread_listening;
mic_tcp_sock mysockets[MAX_SOCKET];

int index_first_elmnt;
mic_tcp_pdu * packet_window[WINDOW_SIZE];
TIMER_MNGMNT_BOX timerBox;
short int timer_state_window[WINDOW_SIZE];
short int window_closed;

mic_tcp_sock_addr socket_to_addr_dest[MAX_SOCKET];  //tableau où l'on stocke les addreses destinatrices des sockets


short int timer_state_window[WINDOW_SIZE]; // 1 = timer is running; 0 = timer is done (timeout); -1 = timer is disabled;
pthread_t timer_tid_window[WINDOW_SIZE]; // Up to match a state to thread

short int timer_HS_state;
pthread_t timer_HS_tid;



/*************************
 * Fonctions Utilitaires *
 *************************/
int initialize_components(start_mode mode)
{
    struct hostent * hp;
    struct sockaddr_in local_addr;

    if(initialized != -1) return initialized;
    if((sys_socket = socket(AF_INET, SOCK_DGRAM, 0)) == -1) return -1;
    else initialized = 1;

    if(initialized != -1)
    {
        TAILQ_INIT(&app_buffer_head);
        pthread_cond_init(&buffer_empty_cond, 0);
        memset((char *) &local_addr, 0, sizeof(local_addr));
        memset((char *) &remote_addr, 0, sizeof(remote_addr));
        local_addr.sin_family = AF_INET;
        remote_addr.sin_family = AF_INET;

        

        if(mode == SERVER)
        {
            local_addr.sin_port = htons(API_CS_Port);
            local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        }
        else
        {
            local_addr.sin_port = htons(API_SC_Port);
            local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        }
        
        initialized = bind(sys_socket, (struct sockaddr *) &local_addr, sizeof(local_addr));

        if(initialized != -1)
        {
            if(mode == SERVER)
            {
                remote_addr.sin_port = htons(API_SC_Port);
            }
            else
            {
                remote_addr.sin_port = htons(API_CS_Port);
            }

            hp = gethostbyname("localhost");
            memcpy (&(remote_addr.sin_addr.s_addr), hp->h_addr, hp->h_length);
            initialized = 1;
        }


    }
    

    if(initialized == 1)
    {
        thread_listening = 1;
        if( mode == SERVER )
        {
            for(int i=0; i<WINDOW_SIZE; i++)
                packet_window[i] = NULL;

            pthread_create (&listen_th, NULL, listening, "1");

        }
        else // CLIENT
        {
            //Initialisation of variables
            window_closed = 0;
            index_first_elmnt = 0;
            for(int i=0; i<WINDOW_SIZE; i++)
            {
                timer_state_window[i] = -1; // All timer are disabled
                timer_HS_state = -1;
                packet_window[i] = NULL;
            }
            pthread_create (&retransmission_tid, NULL, retransmission_th, NULL);
            pthread_create (&listen_th, NULL, listening, "2");
        }
        
    }

    return initialized;
}


int IP_send(mic_tcp_pdu pk, mic_tcp_sock_addr addr)
{

    int result = 0;

    if(initialized == -1) {
        result = -1;

    } else {
        mic_tcp_payload tmp = get_full_stream(pk);
        int sent_size =  mic_tcp_core_send(tmp);

        free (tmp.data);

        /* Correct the sent size */
        result = (sent_size == -1) ? -1 : sent_size - API_HD_Size;
    }

    return result;
}

int IP_recv(mic_tcp_pdu* pk, mic_tcp_sock_addr* addr, unsigned long timeout)
{
    int result = -1;

    struct timeval tv;
    struct sockaddr_in tmp_addr;
    socklen_t tmp_addr_size = sizeof(struct sockaddr);

    /* Send data over a fake IP */
    if(initialized == -1) {
        return -1;
    }

    /* Compute the number of entire seconds */
    tv.tv_sec = timeout / 1000;
    /* Convert the remainder to microseconds */
    tv.tv_usec = (timeout - tv.tv_sec * 1000) * 1000;

    /* Create a reception buffer */
    int buffer_size = API_HD_Size + pk->payload.size;
    char *buffer = malloc(buffer_size);

    if ((setsockopt(sys_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv))) >= 0) {
       result = recvfrom(sys_socket, buffer, buffer_size, 0, (struct sockaddr *)&tmp_addr, &tmp_addr_size);
    }

    if (result != -1) {
        /* Create the mic_tcp_pdu */
        memcpy (&(pk->header), buffer, API_HD_Size);
        pk->payload.size = result - API_HD_Size;
        memcpy (pk->payload.data, buffer + API_HD_Size, pk->payload.size);

        /* Generate a stub address */
        if (addr != NULL) {
            addr->ip_addr = "localhost";
            addr->ip_addr_size = strlen(addr->ip_addr) + 1; // don't forget '\0'
            addr->port = pk->header.source_port;
        }

        /* Correct the receved size */
        result -= API_HD_Size;
    }

    /* Free the reception buffer */
    free(buffer);

    return result;
}

mic_tcp_payload get_full_stream(mic_tcp_pdu pk)
{
    /* Get a full packet from data and header */
    mic_tcp_payload tmp;
    tmp.size = API_HD_Size + pk.payload.size;
    tmp.data = malloc (tmp.size);

    memcpy (tmp.data, &pk.header, API_HD_Size);
    memcpy (tmp.data + API_HD_Size, pk.payload.data, pk.payload.size);

    return tmp;
}

mic_tcp_payload get_mic_tcp_data(ip_payload buff)
{
    mic_tcp_payload tmp;
    tmp.size = buff.size-API_HD_Size;
    tmp.data = malloc(tmp.size);
    memcpy(tmp.data, buff.data+API_HD_Size, tmp.size);
    return tmp;
}


mic_tcp_header get_mic_tcp_header(ip_payload packet)
{
    /* Get a struct header from an incoming packet */
    mic_tcp_header tmp;
    memcpy(&tmp, packet.data, API_HD_Size);
    return tmp;
}

int full_send(mic_tcp_payload buff)
{
    int result = 0;

    result = sendto(sys_socket, buff.data, buff.size, 0, (struct sockaddr *)&remote_addr, sizeof(remote_addr));

    return result;
}

int mic_tcp_core_send(mic_tcp_payload buff)
{
    int random = rand();
    int result = buff.size;
    int lr_tresh = (int) round(((float)loss_rate/100.0)*RAND_MAX);

    if(random > lr_tresh) {
        result = sendto(sys_socket, buff.data, buff.size, 0, (struct sockaddr *)&remote_addr, sizeof(struct sockaddr));
    } else {
        printf("[MICTCP-CORE] Perte du paquet\n");
    }

    return result;
}

int app_buffer_get(mic_tcp_payload app_buff, int block_state)
{
    /*
    If block_state == 1 then app_buffer_get will block the process until it get a sent pdu.
        It returns the size of the sent pdu.
    If block_state == 0 then app_buffer_get return -1 if the queue is empty and the size
        of the pdu there is at least one in the queue.
    */
    
    int result = -1;
    
    /* A pointer to a buffer entry */
    struct app_buffer_entry * entry;
    
    
    /* Lock a mutex to protect the buffer from corruption */
    pthread_mutex_lock(&lock);
    
    if( block_state )
    {
        
        /* If the buffer is empty, we wait for insertion */
        while(app_buffer_head.tqh_first == NULL)
        {
            pthread_cond_wait(&buffer_empty_cond, &lock);
        }
        
        /* When we execute the code below, the following conditions are true:
        - The buffer contains at least 1 element
        - We hold the lock on the mutex
        */

        /* The entry we want is the first one in the buffer */
        entry = app_buffer_head.tqh_first;

        /* How much data are we going to deliver to the application ? */
        result = min_size(entry->bf.size, app_buff.size);

        /* We copy the actual data in the application allocated buffer */
        memcpy(app_buff.data, entry->bf.data, result);
        
        
        /* We remove the entry from the buffer */
        TAILQ_REMOVE(&app_buffer_head, entry, entries);

        /* Clean up memory */
        free(entry->bf.data);
        free(entry);
    }
    else
    {
        if( ! TAILQ_EMPTY(&app_buffer_head) )
        {
            /* When we execute the code below, the following conditions are true:
        - The buffer contains at least 1 element
        - We hold the lock on the mutex
        */

            /* The entry we want is the first one in the buffer */
            entry = app_buffer_head.tqh_first;
    
            /* How much data are we going to deliver to the application ? */
            result = min_size(entry->bf.size, app_buff.size);
    
            /* We copy the actual data in the application allocated buffer */
            memcpy(app_buff.data, entry->bf.data, result);
            
            
            /* We remove the entry from the buffer */
            TAILQ_REMOVE(&app_buffer_head, entry, entries);
    
    
            /* Clean up memory */
            free(entry->bf.data);
            free(entry);
        }
    }
    
    /* Release the mutex */
    pthread_mutex_unlock(&lock);

    return result;
}

void app_buffer_put(mic_tcp_payload bf)
{
    /* Prepare a buffer entry to store the data */
    struct app_buffer_entry * entry = malloc(sizeof(struct app_buffer_entry));
    entry->bf.size = bf.size;
    entry->bf.data = malloc(bf.size);
    memcpy(entry->bf.data, bf.data, bf.size);

    /* Lock a mutex to protect the buffer from corruption */
    pthread_mutex_lock(&lock);

    /* Insert the packet in the buffer, at the end of it */
    TAILQ_INSERT_TAIL(&app_buffer_head, entry, entries);

    /* Release the mutex */
    pthread_mutex_unlock(&lock);

    /* We can now signal to any potential thread waiting that the buffer is
       no longer empty */
    pthread_cond_broadcast(&buffer_empty_cond);
}



void* listening(void* arg)
{
    mic_tcp_pdu pdu_tmp;
    int recv_size;
    mic_tcp_sock_addr remote;
    thread_listening = 1;

    pthread_mutex_init(&lock, NULL);

    printf("[MICTCP-CORE] Demarrage du thread de reception reseau...\n");

    const int payload_size = 1500 - API_HD_Size;
    pdu_tmp.payload.size = payload_size;
    pdu_tmp.payload.data = malloc(payload_size);


    while( thread_listening )
    {
        pdu_tmp.payload.size = payload_size;
        recv_size = IP_recv(&pdu_tmp, &remote, 0);

        if(recv_size != -1)
        {
            process_received_PDU(pdu_tmp, remote);
        } else {
            /* This should never happen */
            printf("Error in recv\n");
        }
    }
    printf("Listening thread ends ! \n");
    return NULL;
}


void set_loss_rate(unsigned short rate)
{
    loss_rate = rate;
}

void print_header(mic_tcp_pdu bf)
{
    mic_tcp_header hd = bf.header;
    printf("\nSP: %d, DP: %d, SEQ: %d, ACK: %d", hd.source_port, hd.dest_port, hd.seq_num, hd.ack_num);
}

unsigned long get_now_time_msec()
{
    return ((unsigned long) (get_now_time_usec() / 1000));
}

unsigned long get_now_time_usec()
{
    struct timespec now_time;
    clock_gettime( CLOCK_REALTIME, &now_time);
    return ((unsigned long)((now_time.tv_nsec / 1000) + (now_time.tv_sec * 1000000)));
}

int min_size(int s1, int s2)
{
    if(s1 <= s2) return s1;
    return s2;
}


/*
    TIMER functions
*/

void* timer_HS_th(void* a)
{
    int ms = *(int*) a;
    struct timespec set_time, left_time;
    set_time.tv_sec = ms / 1000; /* seconds */
    set_time.tv_nsec = (ms - set_time.tv_sec*1000) * 1000000; /* nanoseconds */
    //printf("We have %ld secs and %ld msecs !\n", set_time.tv_sec, set_time.tv_nsec/1000000);
	nanosleep( &set_time, &left_time );
    timer_HS_state = 0;
  //  pthread_cond_signal(&connect_cond);
    free(a);
    return NULL;

}

void* timer_th(void* arg)
{
    THRD_TIMER_ARG* tm_arg = (THRD_TIMER_ARG*)arg;
    struct timespec set_time, left_time;
    set_time.tv_sec = tm_arg->millisec / 1000; /* seconds */
    set_time.tv_nsec = (tm_arg->millisec - set_time.tv_sec*1000) * 1000000; /* nanoseconds */
    //printf("We have %ld secs and %ld msecs !\n", set_time.tv_sec, set_time.tv_nsec/1000000);
	nanosleep( &set_time, &left_time );
    timer_state_window[tm_arg->index_timer] = 0; //We end the timer but not disable it
    
    pthread_mutex_lock(&timeout_mutex);
    timeout_th = 1;
    pthread_mutex_unlock(&timeout_mutex);

    pthread_cond_signal(&timeout_cond);
    free(tm_arg);
    return NULL;
}

int stop_timer(int index_timer){
    int r;
    // We take the mutex, cancel the thread before to ensure it won't modify the flag after us here
    pthread_mutex_lock(&timeout_mutex);
    r = pthread_cancel(timer_tid_window[index_timer]);
    timer_state_window[index_timer] = -1;
    pthread_mutex_unlock(&timeout_mutex);

    return r;
}

void launch_timer(int index_timer, int millisec){
    THRD_TIMER_ARG* tm_arg = malloc(sizeof(THRD_TIMER_ARG));
	tm_arg->millisec = millisec;
    tm_arg->index_timer = index_timer;

    // We launch the timer before starting update the flag
    if(pthread_create(timer_tid_window + index_timer, NULL, timer_th, tm_arg) == -1){
        perror("Error launch_timer ");
    }

    pthread_mutex_lock(&timeout_mutex);
    timer_state_window[index_timer] = 1;
    pthread_mutex_unlock(&timeout_mutex);
}

void launch_HS_timer(int ms){
    timer_HS_state = 1;
    int* a_ms = malloc(sizeof(int));
    *a_ms = ms;
    if(pthread_create(&timer_HS_tid, NULL, timer_HS_th, a_ms) == -1){
        perror("Echec launch_timer ");
    }
}

void stop_HS_timer(int ms){
    timer_HS_state = -1;
    pthread_cancel(timer_HS_tid);
}

int check_HS_timer()
{
    return timer_HS_state;
}


int check_timer(int index_timer){
    int r;
    pthread_mutex_lock(&timeout_mutex);
    r = timer_state_window[index_timer];
    pthread_mutex_unlock(&timeout_mutex);

    return r;
}





void* retransmission_th(void *arg){ // Thread in charge of the retransmission of packets on the sender side
    while(1){
        //while(none_timeout); // Wait until timeout occurs
        
        pthread_mutex_lock(&timeout_mutex);
        while( !timeout_th )
        {
            pthread_cond_wait(&timeout_cond, &timeout_mutex);
        }
        timeout_th = 0;
        pthread_mutex_unlock(&timeout_mutex); // We release the mutex because (check&stop)_timer are thread_safe function


        
        for(int i=0; i<WINDOW_SIZE; i++)
        {
            if(check_timer(i) == 0){ // timeout
                stop_timer(i);
                pthread_mutex_lock(&ew_state_mutex);
                IP_send(*packet_window[i], *timerBox.destination_addr);
                printf(" [Retrans THREAD] Retransmission happen: index <%d> seq_num <%d>  \n", i, packet_window[i]->header.seq_num);
                pthread_mutex_unlock(&ew_state_mutex);
            }
        }
    }
}


