#include "../../includes/ft_nmap.h"

extern struct s_bag *list;

// if the number is in the range specified, return true, if not, return false
static bool in_range(int start, int end, char *c)
{
	int num = ft_atoi(c);
	return (num >= start && num <= end);
}

// return 1 if the str of the index has already been treated, if not, return 0
int	is_char_in_double(char **tab, int i)
{
	int	j;

	j = 0;
	while (j < i)
	{
		if (ft_atoi(tab[i]) == ft_atoi(tab[j]))
			return (1);
		j++;
	}
	return (0);
}

// return the total numbers of "commas" ports without the doubles
static int len_indiv_without_doubles(char **tab)
{
	int		i;
	int		j;
	int		count;

	count = 0;
	i = 0;
	while (tab[i])
	{
		j = 0;
		while (j < i)
		{
			if (ft_atoi(tab[i]) == ft_atoi(tab[j]))
			{
				count++;
				break;
			}
			j++;
		}
		i++;
	}
	return (count);
}

// count the number of doubles out of the range, only in the commas section
static int	doubles_out_of_range(char **tab)
{
	int		i;
	int		count;

	i = 0;
	count = 0;
	while (tab[i])
	{
		if (is_char_in_double(tab, i))
		{
			if (in_range(list->port_from, list->port_to, tab[i]) == false)
				count++;
		}
		i++;
	}
	return (count);
}

static void init_range_ports(char **range, char **indiv)
{
	int		i;
	int		j;
	int		count;

	j = 0;
	count = 0;
	
	list->port_from = ft_atoi(range[0]);
	list->port_to = ft_atoi(range[1]);
	
	i = list->port_from;

	while (i <= list->port_to)
	{
		if (i >= RANGE_PORT || i < 0)
			print_error_and_free_list("Error: One of the ports exceed the limit of ports computer range: 0-65535\n", 0); 
		j = 0;

		while (indiv[j])
		{
			if (i == ft_atoi(indiv[j])) // count one in much but OK
				count++;
			j++;
		}
		i++;
	}
	count += doubles_out_of_range(indiv);
	list->len_tab_ports_indiv = ft_strlen_tab(indiv) - count;
}

// check la range 0-0
int init_ports(char **indiv, char **range)
{
	int j = 0;
	int	i = 0;
	int	tmp = 0;

	if (range)
	{
		init_range_ports(range, indiv);
	}
	else
		list->len_tab_ports_indiv = ft_strlen_tab(indiv) - len_indiv_without_doubles(indiv);
	list->tab_ports_indiv = (int *)malloc(sizeof(int) * list->len_tab_ports_indiv);
	if (!list->tab_ports_indiv)
		return (printf ("Error: allocation failed for the indiv int tab.\n"));
	list->tab_ports_indiv = ft_memset(list->tab_ports_indiv, 0, (sizeof(int) * list->len_tab_ports_indiv));
	while (indiv[j])
	{
		if (in_range(list->port_from, list->port_to, indiv[j]) == false && !is_char_in_double(indiv, j))
		{
			tmp = ft_atoi(indiv[j]);
			if (tmp >= RANGE_PORT || tmp < 0)
				print_error_and_free_list("Error: One of the ports exceed the limit of ports computer range: 0-65535\n", 0);
			list->tab_ports_indiv[i] = tmp;
			i++;
		}
		j++;
	}
	return (0);
}

