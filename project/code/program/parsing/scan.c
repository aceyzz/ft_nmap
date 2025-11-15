#include "../../includes/ft_nmap.h"

extern struct s_bag *list;

static void scans_count()
{
	int	i = 0;

	if (list->scans.all == true)
	{
		list->count_scans = 6;
		return ;
	}
	if (list->scans.null == true)
		i++;
	if (list->scans.fin == true)
		i++;
	if (list->scans.xmas == true)
		i++;
	if (list->scans.ack == true)
		i++;
	if (list->scans.udp == true)
		i++;
	if (list->scans.syn == true)
		i++;
	list->count_scans = i;
}

void check_scan_option(char *av)
{
	if (list->scan == true)
		print_error_and_free_list("Error : you cannot have two times the same option SCAN.\n", 0);

	int		i = 0;
	char 	**tab = ft_split(av, ',');
	if (!tab)
		print_error_and_free_list("Something went wrong with ft_split.\nEnding the program...\n", 1);

	while (tab[i])
	{
		if (!ft_strcmp(tab[i], "SYN"))
			list->scans.syn = true;
		else if (!ft_strcmp(tab[i], "NULL"))
			list->scans.null = true;
		else if (!ft_strcmp(tab[i], "FIN"))
			list->scans.fin = true;
		else if (!ft_strcmp(tab[i], "XMAS"))
			list->scans.xmas = true;
		else if (!ft_strcmp(tab[i], "ACK"))
			list->scans.ack = true;
		else if (!ft_strcmp(tab[i], "UDP"))
			list->scans.udp = true;
		else
		{
			printf ("Error: scan type unknown: %s\n", tab[i]);
			free_tab (tab);
			spread_help_option(); 
		}
		i++;
	}
	list->scan = true;
	scans_count();
	free_tab (tab);
}