#include "../../includes/ft_nmap.h"

extern struct s_bag *list;

// Check the basic error inputs from the --ports option
static bool basic_parsing_ports_option(char *str)
{
	bool	dash;

	dash = false;
	if (!only_digits_comma_dash_in_str(str))
		print_error_and_free_list("Error: the ports option do not support one of the caracters entered.\n--ports ports to scan (eg: 1-10 or 1,2,3 or 1,5-15)\n", 0);
	else if (dash_number(str))
		print_error_and_free_list("Error: the ports option do not support several ranges.\n--ports ports to scan (eg: 1-10 or 1,2,3 or 1,5-15)\n", 0);
	else if (misplaced_comma_dash(str))
		print_error_and_free_list("Error: one or more comma or dash are misplaced in the ports option.\n--ports ports to scan (eg: 1-10 or 1,2,3 or 1,5-15)\n", 0);
	else if (ft_strchr(str, (int)'-'))
	{
		dash = true;
		if (!commas_then_single_dash(str))
			print_error_and_free_list("Error: range is misplaced in the ports option.\n--ports ports to scan (eg: 1-10 or 1,2,3 or 1,5-15)\n", 0);	
	}
	return (dash);
}

// Saving data, if there is range numbers, and/or "commas" numbers option for ports
static void init_status_of_ports_type(char **dash_split)
{
	if (list->len_tab_ports_indiv > 0)
		list->ports_indiv = true;
	if (dash_split)
		list->ports_range = true;
}

// Initialise and parse all the ports option
void check_ports_option(char *str)
{
	char	**dash_split = NULL;
	int 	total_range = 0;
	bool	dash = basic_parsing_ports_option(str);
	char	**comma_split = ft_split(str, ',');
	
	if (list->ports_range == true || list->ports_indiv == true)
		print_error_and_free_list("Error : you cannot have two times the same option PORTS.\n", 0);

	if (!comma_split)
		print_error_and_free_list("Error: something went wrong with ft_split function.\n", 1); 

	get_total_indiv_ports(comma_split);
	if (dash == true)
	{
		dash_split = ft_split(comma_split[ft_strlen_tab(comma_split) - 1], '-');
		if (!dash_split)
			free_tab_and_exit(comma_split, "Error: something went wrong with ft_split function.\n", 1);
		total_range = get_total_range_ports(dash_split);
		if (total_range < 0)
			free_tabs_and_exit(comma_split, dash_split, "Error: range ports is not in a valid format.\n", 0);
	}
	if (init_ports(comma_split, dash_split))
		free_tabs_and_exit(comma_split, dash_split, "", 0);
	init_status_of_ports_type(dash_split);
	if ((total_range + list->len_tab_ports_indiv) > 1024)
		free_tabs_and_exit(comma_split, dash_split, "Error: combined individuals and range numbers of port is to high.\nThe program does not accept more than 1024 ports to scan.\n", 0);
	list->count_ports = total_range + list->len_tab_ports_indiv;
	free_tab(comma_split);
	free_tab(dash_split);
}