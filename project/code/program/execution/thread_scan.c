#include "../../includes/ft_nmap.h"

extern struct s_bag *list;

static void    *routine(void *infos)
{
    t_infos      *data = infos;
    int         protocol;
    int         scan = 1;
    int         len_packet;

    while (scan < TOTAL_TYPE)
    {
        if (data->scan[scan] == true)
            break;
        scan++;
    }
    
    t_packet_header packet = create_pckt(scan);
    if (scan == UDP)
    {
        protocol = IPPROTO_UDP;
        len_packet = sizeof(struct udphdr);
    }
    else
    {
        protocol = IPPROTO_TCP;
        len_packet = sizeof(struct tcphdr);
    }
    // raw socket for packet sending
    int fd = create_socket(protocol, data);
    for (struct s_ip *ip = list->res; ip != NULL; ip = ip->next)
    {
        // while loop int tab port
        for (int port = 0; port < RANGE_PORT; port++)
        {
            // default status to filtred
            if (data->port[port] == true)
            {
                pthread_mutex_lock(&list->state_mutex);
                ip->state[scan][port] = FILTERED;
                // if the scan is UDP, FIN, NUL, XMAS it's also assign to open
                if (scan == FIN || scan == NUL || scan == XMAS || scan == UDP)
                    ip->state[scan][port] += OPEN;
                pthread_mutex_unlock(&list->state_mutex);
                // set dest port of the packet and calculate the checksum
                if (protocol == IPPROTO_TCP)
                {
                    packet.tcp.dest = htons(port);
                    packet.tcp.check = 0;
                }
                else
                {
                    packet.udp.dest = htons(port);
                    packet.udp.check = 0;
                }
                init_checksum(protocol, &packet, len_packet, ip);
                if (sendto(fd, &packet, len_packet, 0, &ip->addr.base, ip->addrlen) < 0)
                {
                    close (fd);
                    free (data);
                    data = NULL;
                    print_error_and_free_list("Error: something went wrong with  sendto() function.\nClosing the program...\n", 1); 
                }
                ft_usleep(1000);     
            }
        }
    }
    close (fd);
    free (data);
    data = NULL;
    return (NULL);
}

// distibute threads per scan type asked
// distribute ports asked per scan types
static void ft_setter(int total, int *setter, int start, int end, bool *ele)
{
    ft_bzero(setter, sizeof(int) * (end - start));
    int current = start;
    for (int i = 0; i < total; i++)
    {
        if (current >= end)
            current = start;
        if (ele != NULL && !ele[current]) // check if the ele in the list is asked or not (port to scan, scan type to make or not)
            i--;
        else
            setter[current]++;
        current++;
    }
}

bool is_scan_asked(int scan)
{
    if ((list->scans.all || list->scans.null) && scan == NUL)
        return (true);
    if ((list->scans.all || list->scans.syn) && scan == SYN)
        return (true);
    if ((list->scans.all || list->scans.ack) && scan == ACK)
        return (true);
    if ((list->scans.all || list->scans.fin) && scan == FIN)
        return (true);
    if ((list->scans.all || list->scans.xmas) && scan == XMAS)
        return (true);
    if ((list->scans.all || list->scans.udp) && scan == UDP)
        return (true);
    return (false);
}

void launch_thread_scan()
{
    pthread_t   threads[list->speedup_val];
    int         thread_id = 0;
    int         setter[TOTAL_TYPE]; // int tab size of scan total nbr

    ft_setter(list->speedup_val, setter, 1, TOTAL_TYPE, list->info_scan); // set for each scan type activated the nbr of threads assigned to them 

    for (int scan = 1; scan < TOTAL_TYPE; scan++)
    {
        if (list->info_scan[scan] == true)
        {
            int threads_nbr[setter[scan]]; // give to a thread int tab the len of thread nbr assigned for the scan type
        
            ft_setter(list->count_ports, threads_nbr, 0, setter[scan], NULL); // give to the scan type the nbr of ports to scan for each threads
        
            int iport = 0;
            for (int thread_launched = 0; thread_launched < setter[scan]; thread_launched++)
            {
                t_infos *set_to_scan = ft_calloc(1, sizeof(t_infos));
                if (!set_to_scan)
                    print_error_and_free_list("Error: something went wrong with  ft_calloc() function.\nClosing the program...\n", 1); 

                int total_to_send = threads_nbr[thread_launched]; // total to send= value of the number of ports to send for this indexed thread

                for (int i = 1; i < TOTAL_TYPE; i++)
                    set_to_scan->scan[i] = false;
                set_to_scan->scan[scan] = true; // set the struct only for the scan type that we point in the for loop

                for (int i = 0; i < RANGE_PORT; i++)
                    set_to_scan->port[i] = false;
                
                for (; iport < RANGE_PORT && total_to_send > 0; iport++) // set the range of ports to scan for the thread that we're pointing on
                {
                    if (list->info_port[iport] == true)
                    {
                        set_to_scan->port[iport] = true;
                        total_to_send--;
                    }
                }
                if (pthread_create(&threads[thread_id++], NULL, routine, set_to_scan) < 0)
                {
                    free (set_to_scan);
                    print_error_and_free_list("Error: something went wrong with  pthread_create() function.\nClosing the program...\n", 1);
                }
            }
        }
    }
    for (int i = 0; i < thread_id; i++) {
        int result = pthread_join(threads[i], NULL);
        if (result != 0) {
            print_error_and_free_list("Error: something went wrong with pthread_join() function.\nClosing the program...\n", 1);
        }
    }
}