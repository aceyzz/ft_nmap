#include "../../includes/ft_nmap.h"

extern struct s_bag *list;

int	ft_strcmp(const char *s1, const char *s2)
{
	size_t	i;

	i = 0;
	while (s1[i] && s2[i] && s1[i] == s2[i])
	{
		i++;
	}
	return ((unsigned char)s1[i] - (unsigned char)s2[i]);
}

char	*ft_strcpy(char *dest, char *src)
{
	int	i;
	int	j;

	i = 0;
	j = 0;
	if (src)
	{
		while (src[i] != '\0')
		{
			dest[j] = src[i];
			i++;
			j++;
		}
		dest[j] = '\0';
	}
	return (dest);
}

int ft_strlen_tab(char **tab)
{
	int		i;

	i = 0;
	while (tab[i])
	{
		i++;
	}
	return (i);
}

char ft_strcat(char *dest, const char *src)
{
    int i = 0;
    int j = 0;
    while (dest[i])
        i++;
    while (src[j]) {
        dest[i] = src[j];
        i++;
        j++;
    }
    dest[i] = '\0';
    return *dest;
}

void	ft_usleep(int microseconds)
{
	struct	timeval	start;
	struct	timeval	current;
	struct	timeval	end;

	gettimeofday(&start, NULL);
	end.tv_sec = start.tv_sec + (microseconds / 1000000);
	end.tv_usec = start.tv_usec + (microseconds % 1000000);
	if (end.tv_usec >= 1000000)
	{
		end.tv_sec += 1;
		end.tv_usec -= 1000000;
	}
	while (1)
	{
		gettimeofday(&current, NULL);
		if (current.tv_sec < end.tv_sec || (current.tv_sec >= end.tv_sec && current.tv_usec < end.tv_usec))
			break ;
	}
}

void	ft_timeout()
{
	pcap_breakloop(list->handle);
	list->stop_nmap = true;
}