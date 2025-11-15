#include "../../includes/ft_nmap.h"

extern struct s_bag *list;

static	void check_speedup_logic()
{
	if (list->speedup_val < list->count_scans)
	{
		list->speedup_val = list->count_scans;
		// printf ("Info: optimizing the speedup option, so each type scan can have it own threads. Speedup changed to: %d\n", list->speedup_val);
	}
	else if (list->speedup_val > (list->count_scans * list->count_ports))
	{
		list->speedup_val = (list->count_scans * list->count_ports);
		// printf ("Info: speedup option is upper than the total of scan to realise. Adjusting speedup to %d, so no more threads will be unused\n", list->speedup_val);
	}
}

void 	check_speedup_option(char *str)
{
	int	speedup = 0;

	if (list->speedup == true)
		print_error_and_free_list("Error : you cannot have two times the same option SPEEDUP.\n", 0);

	if (!only_digits_in_str(str))
		print_error_and_free_list("Error: the speedup option only take digits.\nFor more informations please refer to the --help menu.\n", 0);
	speedup = ft_atoi(str);
	if (speedup > 250)
		print_error_and_free_list ("Error: the speedup option is too high.\nThe maximum is 250.\n", 0);
	list->speedup_val = speedup;
	list->speedup_origins = speedup;
	check_speedup_logic();
	if (list->speedup_val > 1)
		list->speedup = true;
}