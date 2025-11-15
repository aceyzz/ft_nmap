#include "../../includes/ft_nmap.h"

extern struct s_bag *list;

// Print error msg, exit with code
void print_error_and_exit(char *str, int code)
{
	printf ("%s", str);
	exit (code);
}

void free_list()
{
	if (list)
	{
		if (list->tab_ports_indiv)
		{
			free (list->tab_ports_indiv);
			list->tab_ports_indiv = NULL;
		}
		if (list->ip_str)
		{
			free_tab (list->ip_str);
			list->ip_str = NULL;
		}
		if (list->res)
		{
			free_linked_list();
			list->res = NULL;
		}
		free (list);
		list = NULL;
	}
}

// Print error msg, free list, exit with code
void print_error_and_free_list(char *str, int code)
{
	free_list(list);
	print_error_and_exit(str, code);
}

void	free_tab(char **tab)
{
	int		i;

	i = 0;
	if (tab)
	{
		while (tab[i])
		{
			free (tab[i]);
			i++;
		}
		free (tab);
		tab = NULL;
	}
}

// Free the tab in arg, print error msg, free list, exit with code
void	free_tab_and_exit(char **tab, char *str, int code)
{
	free_tab(tab);
	print_error_and_free_list(str, code); 
}

// Free both tabs in arg, print error msg, free list, exit with code
void	free_tabs_and_exit(char **tab1, char **tab2, char *str, int code)
{
	free_tab(tab1);
	free_tab(tab2);
	print_error_and_free_list(str, code); 
}

// free the linked list ip
void	free_linked_list()
{
	t_ip	*tmp;

	if (NULL == list->res)
		return ;
	while (list->res)
	{
		tmp = list->res->next;
		free(list->res);
		list->res = tmp;
	}
	list->res = NULL;
}