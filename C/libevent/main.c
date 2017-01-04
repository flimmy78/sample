#include <stdio.h>
#include <event.h>
//#include <event2/event_struct.h>
//#include <event2/event_compat.h>

struct event myev;  
struct timeval tv;  

void time_cb(int fd, short event, void *argc)  
{  
    printf("timer wakeup\n");  
    event_add(&myev, &tv); // reschedule timer  
}  
int main()  
{  
    struct event_base *base = event_init();  
    tv.tv_sec = 1; // 10s period  
    tv.tv_usec = 0;  
    evtimer_set(&myev, time_cb, NULL);  
    event_add(&myev, &tv);  
    event_base_dispatch(base);  
}  
