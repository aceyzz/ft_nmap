#include "../../includes/ft_nmap.h"

extern struct s_bag *list;

t_packet_header     create_pckt(int scan)
{
    t_packet_header packet;
    ft_memset(&packet, 0, sizeof(t_packet_header));

    // UDP packet it only require source port and the len
    if (scan == UDP) 
    {
        packet.udp.source = htons(scan);
        packet.udp.len = htons(sizeof(struct udphdr));
        return packet;
    }

    // TCP pqcket it require the source port, window size and data offset
    packet.tcp.source = htons(scan);
    packet.tcp.doff = 5; // 5*4 bytes (32 bits) == 20 bytes => header size

    // flag init to send the right scan type
    if (scan == ACK)
        packet.tcp.ack = 1;
    if (scan == SYN)
        packet.tcp.syn = 1;
    if (scan == FIN)
        packet.tcp.fin = 1;
    if (scan == XMAS)
    {
        packet.tcp.fin = 1;
        packet.tcp.psh = 1;
        packet.tcp.urg = 1;
    }
    return (packet);
}

int create_socket(int protocol, void *data)
{
    int fd = socket(AF_INET, SOCK_RAW, protocol);
    if (fd < 0)
    {
        if (data)
            free (data);
        print_error_and_free_list("Error: something went wrong with socket() function.\nClosing the program...\n", 1);
    }
    // size of buff (1Mo) to avoid error msg "no buffer space available" (*)
    int optval = 1024 * 1024;
	if (setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &optval, sizeof(optval)) == -1)
    {
        if (data)
            free (data);
        printf("setsockopt error: %s\n", strerror(errno));
        print_error_and_free_list("Error: something went wrong with setsockopt() function.\nClosing the program...\n", 1);
    }
    // set a specific interface to know from where we received or send the packets
    bind (fd, (struct sockaddr *)&list->ip_src, sizeof(list->ip_src));
    return (fd);
}

bool    port_asked(int port)
{
    int     i = 0;

    if (list->ports_indiv == true)
    {
        while (i < list->len_tab_ports_indiv)
        {
            if (list->tab_ports_indiv[i] == port)
                return (true);
            i++;
        }
    }
    if (list->ports_range == true)
    {
        for (int start = list->port_from; start <= list->port_to; start++)
        {
            if (start == port)
                return (true);
        }
    }
    return (false);
}

void    *execution(int scan)
{
    int             protocol;
    int             len_packet;

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
    int fd = create_socket(protocol, NULL);

    for (struct s_ip *ip = list->res; ip != NULL; ip = ip->next)
    {
        // while loop int tab port
        for (int port = 0; port < RANGE_PORT; port++)
        {
            // default status to filtred
            if (port_asked(port))
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
                    print_error_and_free_list("Error: something went wrong with  sendto() function.\nClosing the program...\n", 1); 
                }
                ft_usleep(1000);         
            }
        }
    }
    close (fd);
    return (NULL);
}

/*
    In case of massive simultaneous scans on several ports the buffer can easily become saturated.
    To avoid this we put the buffer size at 1Mo, good compromise between space available and efficiency.
*/