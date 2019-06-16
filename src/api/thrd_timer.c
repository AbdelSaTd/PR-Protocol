#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>


extern int timerstate = 0; // Declaration and initialization (definition) are allowed by the C standard even though it raise a warning (here).
int timerdone = 0;

void* myth(void* arg)
{
    int ml = (*(int*)arg);
    struct timespec set_time, left_time;
    set_time.tv_sec = ml / 1000; /* seconds */
    set_time.tv_nsec = (ml - set_time.tv_sec*1000) * 1000000; /* nanoseconds */
    //printf("We have %ld secs and %ld msecs !\n", set_time.tv_sec, set_time.tv_nsec/1000000);
	nanosleep( &set_time, &left_time );
    
    timerdone = 1; //We end the timer
    free(arg);
    return NULL;
}


int thrd_timer(int millisec)
{
    if( timerstate )
    {
		if(timerdone == 1)
		{
            timerstate = 0;
            timerdone = 0;
            return 1;
        }
        return 0;
    }
    else
    {
        pthread_t tid=1;
		int* ml = malloc(sizeof(int));
		*ml = millisec;
        if( pthread_create(&tid, NULL, myth, ml) == -1 )
        {
            perror("Echec timer ");
            exit(-1);
        }

		timerstate = 1;

        return timerdone;
    }
}
