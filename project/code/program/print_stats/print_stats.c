#include "../../includes/ft_nmap.h"

extern struct s_bag *list;

static void    print_ip_address()
{
    for (t_ip *tmp = list->res; tmp; tmp = tmp->next)
    {
        if (!tmp->next)
            printf("%s\n", tmp->hostname);
        else
            printf("%s, ", tmp->hostname);
    }
}

static void     scan_to_be_perf()
{
	if (list->scans.null == true || list->scans.all == true)
        printf ("NULL ");
	if (list->scans.fin == true || list->scans.all == true)
		printf ("FIN ");
	if (list->scans.xmas == true || list->scans.all == true)
		printf ("XMAS ");
	if (list->scans.ack == true || list->scans.all == true)
		printf ("ACK ");
	if (list->scans.udp == true || list->scans.all == true)
		printf ("UDP ");
	if (list->scans.syn == true || list->scans.all == true)
		printf ("SYN");
    printf ("\n");
}

static void     print_config()
{
    printf("Scan Configurations\n");
    printf ("Target Ip-Address : ");
    print_ip_address();
    printf ("No of Ports to scan : %d\n", list->count_ports);
    printf ("Scan to be performed : ");
    scan_to_be_perf();
    printf ("No of threads : %d\n", list->speedup_origins);
    printf ("Scanning..\n");
}

static void print_time(struct timeval start)
{
    struct timeval end;

    gettimeofday(&end, NULL);
    double res = end.tv_sec - start.tv_sec + ((end.tv_usec - start.tv_usec) / 1000000.0); // division by 1M to convert in sec and .0 to force the nbrs after commas not just int

    for (int i = 0; i < (int)res; i++)
    {
        printf (".");
        if (i + 1 >= (int)res)
            printf ("\n");
    }
    printf ("Scan took %.5f secs\n", res);
}

void ft_display_stats(struct timeval start)
{
    print_config();
    print_time(start);
    print_result();
    return ;
}