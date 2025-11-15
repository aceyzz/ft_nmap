#include "../../includes/ft_nmap.h"

extern struct s_bag *list;

static void parse_icmp_response(int scan, int port, struct icmphdr *icmp_hdr, struct s_ip *ips)
{
    if (icmp_hdr->type != ICMP_UNREACH) // type reponse is not an expected response to the packet sended : return 
        return ;
    else if (icmp_hdr->code != ICMP_UNREACH_HOST && icmp_hdr->code != ICMP_UNREACH_PROTOCOL && // only the error codes linked to protocol, port, host, or network are analysed
        icmp_hdr->code != ICMP_UNREACH_PORT && icmp_hdr->code != ICMP_UNREACH_NET_PROHIB && // this codes fulfill more details on the reason of the unaccessibility
        icmp_hdr->code != ICMP_UNREACH_HOST_PROHIB && icmp_hdr->code != ICMP_UNREACH_FILTER_PROHIB)
        return ;

    pthread_mutex_lock(&list->state_mutex);
    if (scan == UDP && icmp_hdr->code == ICMP_UNREACH_PORT) // unreacable response for an UDP scan tell us that the port is closed
        ips->state[scan][port] = CLOSED;
    else
        ips->state[scan][port] = FILTERED; // firewall or restrictions network block the access to the port
    pthread_mutex_unlock(&list->state_mutex);
}

// pkthdr= data of the packet
// packet= pointer to datas of captured packet
void    ft_receive_pckt(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    (void) user;
    (void) pkthdr; // ignoring these args we wont use them

    int scan = 0;
    int port = 0;
    int len_iphdr = sizeof(struct iphdr);
    
    packet += 16; // we skip the ethernet header part (not usefull)

    t_packet_header *iphdr = (t_packet_header *)packet; // point to the iphdr of the packet
    t_packet_header *packet_header = (t_packet_header *)(packet + len_iphdr); // point to the header of the packet
    uint8_t protocol = iphdr->ipv4.protocol; // uint8_t is the optimise size to stock protocol value
    t_ip *ips = NULL;
    for (ips = list->res; ips; ips = ips->next)
    {
        if (iphdr->ipv4.saddr == ips->addr.ipv4.sin_addr.s_addr)
            break;
    }
    if (!ips)
        return ;
    if (protocol == IPPROTO_ICMP) // the icmp response include a part of the origin packet sended: iphdr, protocol...
    {
        packet += sizeof(struct icmphdr) + len_iphdr; // point to the iphdr of the original sended packet
        protocol = ((struct iphdr *)packet)->protocol; // identify the original protocol used to send the packet (we will use it later)

        t_packet_header *origin_sended_pckt = (t_packet_header *)(packet + len_iphdr); // point to the original header of the sended packet

        if (protocol == IPPROTO_TCP)
            scan = ntohs(origin_sended_pckt->tcp.source); // because we fulfilled the src port with the scan type info
        else if (protocol == IPPROTO_UDP)
            scan = ntohs(origin_sended_pckt->udp.source);

        if (protocol == IPPROTO_TCP)
            port = ntohs(origin_sended_pckt->tcp.dest);
        else if (protocol == IPPROTO_UDP)
            port = ntohs(origin_sended_pckt->udp.dest);
        parse_icmp_response(scan, port, &packet_header->icmp, ips); // &packet_header->icmp to return a pointer to icmp (we only have pointer to packet_header here)
    }
    else // for UDP or TCP no origin packet but the flags activated in the response packet help us to determine the state of the port for the scan type
    {
        if (protocol == IPPROTO_TCP)
            scan = ntohs(packet_header->tcp.dest); // because we fulfilled the src port (which become dest here as it is a response) with the scan type info
        else
            scan = ntohs(packet_header->udp.dest);
        if (protocol == IPPROTO_TCP)
            port = ntohs(packet_header->tcp.source);
        else
            port = ntohs(packet_header->udp.source);

        pthread_mutex_lock(&list->state_mutex);
        if (scan == UDP || packet_header->tcp.syn) // OPEN SYN if res is SYN/ACK (but syn always present so its easier like that)
            ips->state[scan][port] = OPEN;
        else if (packet_header->tcp.rst)
        {
            if (scan == ACK)
                ips->state[scan][port] = UNFILTERED;
            else
                ips->state[scan][port] = CLOSED;
        }
        pthread_mutex_unlock(&list->state_mutex);
    }
    alarm (5); // relaunch alarm each time we get a packet so it doesn't stop until there is no more packet to catch
}

/*
    (!) Info: Each type of scans for the same port can bring different results because flags activated are stimulating each port in a different way
    So reaction/response will also be different because security elements like firewall, that could respond with different port state for each type of scans
*/