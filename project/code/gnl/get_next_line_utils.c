/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   get_next_line_utils.c                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cduffaut <marvin@42lausanne.ch>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/10/16 14:56:29 by cduffaut          #+#    #+#             */
/*   Updated: 2023/10/16 23:42:05 by csil             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/get_next_line.h"

/*
	Mix of malloc and bzero
	Malloc (type * nbr_of_elements)
	Fill the str with 0
*/
char	*ft_calloc_gnl(size_t count, size_t size)
{
	void	*str;
	size_t	i;

	str = malloc(size * count);
	if (!str)
		return (NULL);
	i = 0;
	while (i < (size * count))
	{
		((char *)str)[i] = 0;
		i++;
	}	
	return (str);
}

// Check if there is \n, return index if yes, -1 if no
int	check_n(char *str)
{
	int	i;

	i = 0;
	while (str[i])
	{
		if (str[i] == '\n')
			return (i);
		i++;
	}
	return (-1);
}

// Allocate and concatenate stock and tmp and return the new str
char	*ft_strjoin_gnl(char *stock, char *tmp)
{
	int		j;
	int		i;
	int		len;
	char	*str;

	len = ft_strlen_gnl(stock) + ft_strlen_gnl(tmp) + 1;
	str = ft_calloc_gnl(len, sizeof(char));
	if (!str)
	{
		free(stock);
		return (NULL);
	}
	i = 0;
	while (stock[i])
	{
		str[i] = stock[i];
		i++;
	}
	j = 0;
	while (tmp[j])
		str[i++] = tmp[j++];
	free(stock);
	str[i] = '\0';
	return (str);
}

// Return the len of the str
int	ft_strlen_gnl(char *str)
{
	int	i;

	i = 0;
	while (str[i])
	{
		i++;
	}
	return (i);
}

/*
	Malloc and duplicate the str in param, until i
	Return the duplicate
*/
char	*ft_strndup_gnl(char *stock, int i)
{
	int		j;
	char	*line;

	j = 0;
	line = ft_calloc_gnl(i + 2, sizeof(char));
	if (!line)
		return (NULL);
	while (j <= i && stock[j])
	{
		line[j] = stock[j];
		j++;
	}
	line[j] = '\0';
	return (line);
}
