#include "../../includes/ft_nmap.h"

extern struct s_bag *list;

int only_digits_in_str(char *str)
{
	int		i = 0;
	
	while (str[i])
	{
		if (!ft_isdigit((int)str[i]))
			return (0);
		i++;
	}
	return (1);
}

int only_digits_comma_dash_in_str(char *str)
{
	int		i;

	i = 0;
	while (str[i])
	{
		if (!ft_isdigit((int)str[i]) && str[i] != '-' && str[i] != ',')
			return (0);
		i++;
	}
	return (1);
}

int	dash_number(char *str)
{
	int		i;
	int		dash;

	i = 0;
	dash = 0;
	while (str[i])
	{
		if (str[i] == '-')
			dash++;
		i++;
	}
	if (dash > 1)
		return (1);
	return (0);
}

int misplaced_comma_dash(char *str)
{
	int		i;

	i = 0;
	while (str[i])
	{
		if (str[i] == ',' || str[i] == '-')
		{
			if (i == 0)
				return (1);
			if (str[i + 1] && (str[i + 1] == '-' || str[i - 1] == ','))
				return (1);
		}
		if (!str[i + 1] && (str[i] == ',' || str[i] == '-'))
		{
			return (1);
		}
		i++;
	}
	return (0);
}

int	commas_then_single_dash(char *str)
{
	int		i;
	bool	dash;

	i = 0;
	dash = false;
	while (str[i])
	{
		if (str[i] == '-')
			dash = true;
		else if ((str[i] == ',') && (dash == true))
			return (0);
		i++;
	}
	return (1);
}

int	get_total_indiv_ports(char **tab)
{
	int		i;
	int		count;

	i = 0;
	count = 0;

	while (tab[i] && !ft_strchr(tab[i], (int)'-'))
	{
		if (!is_char_in_double(tab, i))
			count++;
		if (count > 1024)
			return (count);
		i++;
	}
	return (count);
}

int	get_total_range_ports(char **tab)
{
	int	range_from = atoi(tab[0]);
	int	range_to = atoi(tab[1]);
	
	if (range_to < range_from)
		print_error_and_exit("Error: port range has to be in an ascending order: min-max\n", 1);
	
	int	total_range = (range_to - range_from);

	return (total_range + 1); // it does not count one of the two extremity
}

int	char_count(char *str, char c)
{
	int	i = 0;
	int	counter = 0;

	while (str[i])
	{
		if (str[i] == c)
			counter++;
		i++;
	}
	return (counter);
}

bool	tab_len(char **tab, int len)
{
	int	i = 0;

	while (tab[i])
		i++;
	
	if (i != len)
		return (false);
	
	return (true);
}

bool	non_numeric(char **tab)
{
	int	i = 0;
	int j;

	while (tab[i])
	{
		j = 0;
		while (tab[i][j])
		{
			if (!ft_isdigit(tab[i][j]))
				return (false);	
			j++;
		}
		i++;
	}
	return (true);
}

bool number_range(char **tab)
{
	int	i = 0;
	int	nbr = 0;

	while (tab[i])
	{
		nbr = ft_atoi(tab[i]);
		if (nbr < 0 || nbr > 255)
			return (false);
		i++;
	}
	return (true);
}