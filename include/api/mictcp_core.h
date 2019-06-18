#ifndef MICTCP_CORE_H
#define MICTCP_CORE_H

#include <mictcp.h>
#include <math.h>

/**************************************************************
 * Public core functions, can be used for implementing mictcp *
 **************************************************************/

int initialize_components(start_mode sm);

int IP_send(mic_tcp_pdu, mic_tcp_sock_addr);
int IP_recv(mic_tcp_pdu*, mic_tcp_sock_addr*, unsigned long timeout);
int app_buffer_get(mic_tcp_payload, int block_state);
void app_buffer_put(mic_tcp_payload);

void set_loss_rate(unsigned short);
unsigned long get_now_time_msec();
unsigned long get_now_time_usec();

/**********************************************************************
 * Private core functions, should not be used for implementing mictcp *
 **********************************************************************/

#define API_CS_Port 8524
#define API_SC_Port 8525
#define API_HD_Size 15

typedef struct ip_payload
{
  char* data; /* données transport */
  int size; /* taille des données */
} ip_payload;

int mic_tcp_core_send(mic_tcp_payload);
mic_tcp_payload get_full_stream(mic_tcp_pdu);
mic_tcp_payload get_mic_tcp_data(ip_payload);
mic_tcp_header get_mic_tcp_header(ip_payload);
void* listening(void*);
void print_header(mic_tcp_pdu);

int min_size(int, int);
float mod(int, float);

/* 
  TIMER functions
*/

void stop_timer(int);
void launch_timer(int, int);
int check_timer(int);

void launch_HS_timer(int);
void stop_HS_timer();
int check_HS_timer();

/*
  WINDOW functions
*/

void update_counter_window(int);

/* 
  WINDOW & TIMER variables
*/

// TIMER
typedef struct {
  short int** p_tmr_st_window;
  mic_tcp_sock_addr* destination_addr;
}TIMER_MNGMNT_BOX;

typedef struct {
  int millisec;
  int index_timer;
} THRD_TIMER_ARG;

#define MAX_SOCKET 100
#define WINDOW_SIZE 7 //SIZE OF WINDOW 

extern int counter_window[WINDOW_SIZE]; // 0 = lost packet; 1 = well-sent packet (received by the server)
extern int nb_sent_packet;

extern int index_first_elmnt;
extern mic_tcp_pdu * packet_window[WINDOW_SIZE];
extern TIMER_MNGMNT_BOX timerBox;
extern short int timer_state_window[WINDOW_SIZE];
extern short int window_closed;

extern mic_tcp_sock_addr socket_to_addr_dest[MAX_SOCKET];  //tableau où l'on stocke les addreses destinatrices des sockets



#endif
