#include "../../includes/ft_nmap.h"

extern struct s_bag *list;

void spread_help_option()
{
	print_error_and_free_list("Help Screen\nft_nmap [OPTIONS]\n--help Print this help screen\n--ports ports to scan (eg: 1-10 or 1,2,3 or 1,5-15)\n--ip ip addresses to scan in dot format\n--file File name containing IP addresses to scan,\n--speedup [250 max] number of parallel threads to use\n--scan SYN,NULL,FIN,XMAS,ACK,UDP\n", 0);
}

void check_help_option(int ac, char **av)
{
	int	i = 1;
	while (i < ac)
	{
		if (!ft_strcmp(av[i], "--help"))
			spread_help_option();
		i++;
	}
}