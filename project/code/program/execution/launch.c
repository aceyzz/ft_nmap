#include "../../includes/ft_nmap.h"

extern struct s_bag *list;

void    send_requests()
{
    if (list->speedup == true)
        launch_thread_scan();
    else 
    {
        if (list->scans.all || list->scans.null)
            execution(NUL);
        if (list->scans.all || list->scans.syn)
            execution(SYN);
        if (list->scans.all || list->scans.ack)
            execution(ACK);
        if (list->scans.all || list->scans.fin)
            execution(FIN);
        if (list->scans.all || list->scans.xmas)
            execution(XMAS);
        if (list->scans.all || list->scans.udp)
            execution(UDP);
    }
}