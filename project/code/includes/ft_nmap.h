#ifndef FT_NMAP_H
#define FT_NMAP_H

#define DEBOG 	printf("\n\e[1;32m OK: %d, in %s, in the file: %s\n\e[0m\n", __LINE__, __func__, __FILE__);

#include <stdio.h>        // printf, fflush, fopen, fwrite, fclose, perror, strerror
#include <stdlib.h>       // exit, malloc, free
#include <string.h>       // strerror, memset, memcpy
#include <unistd.h>       // close, getuid, alarm
#include <sys/types.h>    // socket, bind, connect, recvfrom, sendto
#include <sys/socket.h>   // socket, bind, connect, recvfrom, sendto, setsockopt, sockaddr
#include <arpa/inet.h>    // inet_addr, inet_ntoa, inet_pton, inet_ntop, htons, htonl, ntohs, ntohl
#include <netinet/in.h>   // sockaddr_in, IPPROTO_TCP, IPPROTO_UDP
#include <netdb.h>        // getaddrinfo, freeaddrinfo, getservbyport
#include <ifaddrs.h>      // getifaddrs, freeifaddrs
#include <sys/time.h>     // gettimeofday
#include <poll.h>         // poll
#include <pthread.h>      // pthread_create, pthread_exit, pthread_join, pthread_mutex_init, pthread_mutex_lock, pthread_mutex_unlock
#include <signal.h>       // sigaction, sigemptyset
#include <pcap.h>         // pcap_breakloop, pcap_close, pcap_compile, pcap_dispatch, pcap_geterr, pcap_lookupnet, pcap_open_live, pcap_findalldevs, pcap_freealldevs, pcap_setfilter
#include <errno.h>        // errno, gai_strerror
#include <stdbool.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <net/if.h>

// Include your custom libft functions
#include "../libft/libft.h"
#include "get_next_line.h"

// Code for scan res= close=0, open=1, filtered=2, unfilteUNFILTEREDred=3, unfiltered=4
#define CLOSED 0
#define OPEN 1
#define FILTERED 2
#define OPENFILTERED 3
#define UNFILTERED 4

// Code for scan type
#define SYN 1
#define	NUL 2
#define FIN 3
#define	XMAS 4
#define ACK 5
#define UDP 6

// General
#define TOTAL_TYPE 7
#define MAX_IPS 42
#define RANGE_PORT 65536

// Struct for the routine thread func
typedef struct s_infos {
	bool		port[RANGE_PORT];
	bool		scan[TOTAL_TYPE];
}	t_infos;

// Pseudo header for ipv4 format
typedef struct s_phdr
{
    u_int32_t 	src;
    u_int32_t 	dest;
    u_int8_t 	zeros;
    u_int8_t 	protocol;
    u_int16_t 	length;
} t_phdr;

typedef union
{
    struct sockaddr 	base;
    struct sockaddr_in 	ipv4;
} t_sockaddr;

typedef struct s_ip {
    t_sockaddr 		addr;
    socklen_t 		addrlen;

    char 			hostname[NI_MAXHOST]; // NI_MAXHOST constant max len hostname (from getnameinfo())
    int 			state[TOTAL_TYPE][65536]; // (nbr of ports possible from 0 to 65535)

    struct s_ip 	*next;
}		t_ip;

// union that allows you to get the right header needed
typedef union
{
    struct iphdr 	ipv4;
    struct tcphdr 	tcp;
    struct udphdr 	udp;
    struct icmphdr 	icmp;
} t_packet_header;

// structure for scans asked in input
typedef struct s_scan
{
	bool	all;
	bool	null;
	bool	syn;
	bool	ack;
	bool	fin;
	bool	xmas;
	bool	udp;
} 				t_scan;

typedef struct s_bag
{
	bool						stop_nmap;

	bool						ports_range;
	bool						ports_indiv;
	bool						ip;
	bool						file;
	bool						speedup;
	bool						scan;

	int							len_tab_ports_indiv;
	int							*tab_ports_indiv;
	int							port_from;
	int							port_to;
	int							count_ports;
	int							speedup_val;
	int							speedup_origins;

	struct s_scan				scans;
	int							count_scans;

	struct sockaddr_in			ip_src; // binary format
	char						ip_str_src[INET_ADDRSTRLEN];

	char						**ip_str; // singular ele in tab of one ip or several if FILE option

	struct	s_ip				*res;

	bool						info_port[RANGE_PORT]; // boolean list for all the asked ports
	bool						info_scan[TOTAL_TYPE];

	pcap_t 						*handle;
	pthread_mutex_t				state_mutex; // mutex for thread-safe access to state array
}			t_bag;

// --------------------------------- [ PROTOYPES ] --------------------------------- //

// error_and_exit.c
void	print_error_and_exit(char *str, int code);
void	print_error_and_free_list(char *str, int code);
void	free_tab(char **tab);
void	free_tabs_and_exit(char **tab1, char **tab2, char *str, int code);
void	free_tab_and_exit(char **tab, char *str, int code);
void 	free_list();
void	free_linked_list();

// parsing.c
void	ft_parsing(int ac, char **av);
void 	get_addr_in_host(char *ip);
void	check_scan_option(char *av);
void	check_file_option(char *fname);
void 	check_speedup_option(char *str);
void	check_help_option(int ac, char **av);
void 	check_ports_option(char *str);
void 	spread_help_option();

// ip.c
void	add_ip_node_to_list();
char 	*get_ip_by_hostname(char *str);
void	check_ip_option(char *str);

// utils.c
int		ft_strcmp(const char *s1, const char *s2);
int 	ft_strlen_tab(char **tab);
void	print_tab(char **tab);
char	*ft_strcpy(char *dest, char *src);
char 	ft_strcat(char *dest, const char *src);
void	ft_usleep(int microseconds);
void	ft_timeout();

// utils_parsing.c
int 	only_digits_in_str(char *str);
int 	only_digits_comma_dash_in_str(char *str);
int		dash_number(char *str);
int		get_total_indiv_ports(char **comma_split);
int		get_total_range_ports(char **tab);
int		misplaced_comma_dash(char *str);
int		commas_then_single_dash(char *str);
int		char_count(char *str, char c);
bool	tab_len(char **tab, int len);
bool	non_numeric(char **tab);
bool	number_range(char **tab);

// init.c
int 	init_ports(char **indiv, char **range);
int		is_char_in_double(char **tab, int i);

// launch.c, thread_scan.c, execution.c
void    			send_requests();
void    			*execution(int scan);
bool    			port_asked(int port);
int 				create_socket(int protocol, void *data);
t_packet_header     create_pckt(int scan);
bool    			is_scan_asked(int scan);

// receive.c
void    ft_receive_pckt(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet);

// ft_checksum.c
unsigned short	ft_checksum(void *ele, int len);
void			init_checksum(int protocol, t_packet_header *packet, int len_packet, t_ip *ip);

// thread_scan.c
void launch_thread_scan();

// print_stats.c
void 	ft_display_stats(struct timeval start);
void    print_result();
char    *state_in_str(int state);
char    *scan_in_str(int scan);

#endif