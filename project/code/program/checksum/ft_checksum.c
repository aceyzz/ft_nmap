#include "../../includes/ft_nmap.h"

extern struct s_bag *list;

unsigned short	ft_checksum(void *ele, int len)
{
	unsigned short	*buf = (unsigned short *)ele;
	unsigned short	res = 0;
	unsigned int	sum = 0;

	while (len > 1)
	{
		sum += *buf++;
		len -= 2;
	}
	if (len == 1)
		sum += *(unsigned char *)buf;
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	res = (unsigned short)~sum;
	return (res);
}

void	init_checksum(int protocol, t_packet_header *packet, int len_packet, t_ip *ip)
{
	int		len_pshdr = sizeof(t_phdr);
	char	buf[len_pshdr + len_packet];
	ft_memset(buf, 0, len_pshdr + len_packet);
	
	// init and assign the pseudo header at the beggining of the buf
	t_phdr	psheader;
	ft_memset(&psheader, 0, sizeof(t_phdr));

	psheader.src = list->ip_src.sin_addr.s_addr;
	psheader.dest = ip->addr.ipv4.sin_addr.s_addr;
	psheader.protocol = protocol;
	psheader.length = htons(len_packet);

	// cpy the i ppseudo header into the buf
	ft_memcpy(buf, &psheader, len_pshdr);
	// we copy paste the packet after the ip ps header in the buf
	ft_memcpy(buf + len_pshdr, packet, len_packet);

	// assign the result in function of the prototype (TCP or UDP)
	if (protocol == IPPROTO_TCP)
		packet->tcp.check = ft_checksum((void *)buf, len_pshdr + len_packet);
	if (protocol == IPPROTO_UDP)
		packet->udp.check = ft_checksum((void *)buf, len_pshdr + len_packet);
}