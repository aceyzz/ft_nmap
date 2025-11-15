/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   get_next_line.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cduffaut <marvin@42lausanne.ch>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/10/16 19:34:33 by cduffaut          #+#    #+#             */
/*   Updated: 2023/10/16 23:40:23 by csil             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/get_next_line.h"
#include <stdio.h>

char	*get_next_line(int fd)
{
	static char	*stock;
	char		*line;

	if (fd < 0 || BUFFER_SIZE <= 0)
		return (NULL);
	stock = create_stock(stock, fd);
	if (!stock)
		return (NULL);
	line = create_line(stock);
	stock = clean_stock(stock);
	return (line);
}

// Create the stocker for the reads until \n
char	*create_stock(char *stock, int fd)
{
	int		count;
	char	*tmp;

	if (!stock)
		stock = ft_calloc_gnl(1, sizeof(char));
	tmp = ft_calloc_gnl(BUFFER_SIZE + 1, sizeof(char));
	if (!tmp || !stock)
		return (NULL);
	count = 1;
	while (count > 0)
	{
		count = read(fd, tmp, BUFFER_SIZE);
		if (count == -1)
		{
			free(tmp);
			free(stock);
			return (NULL);
		}
		tmp[count] = '\0';
		stock = ft_strjoin_gnl(stock, tmp);
		if (check_n(tmp) != -1)
			break ;
	}
	free(tmp);
	return (stock);
}

// Create the line to return
char	*create_line(char *stock)
{
	int		i;
	char	*str;

	if (stock[0] == '\0')
		return (NULL);
	i = check_n(stock);
	if (i == -1)
		i = ft_strlen_gnl(stock);
	str = ft_strndup_gnl(stock, i - 1);
	if (!str)
		return (NULL);
	return (str);
}

// Clean the stock with the chars only after \n or free
char	*clean_stock(char *stock)
{
	int		i;
	int		j;
	char	*clean;

	if (!stock)
		return (NULL);
	i = check_n(stock);
	if (i == -1)
		return (free_all(stock));
	clean = ft_calloc_gnl(ft_strlen_gnl(stock + i) + 1, sizeof(char));
	if (!clean)
		return (free_all(stock));
	j = 0;
	while (stock[++i])
	{
		clean[j++] = stock[i];
	}
	clean[j] = '\0';
	free(stock);
	return (clean);
}

char	*free_all(char *str)
{
	free(str);
	return (NULL);
}

char	**main_gnl(char *file)
{
	char	*str;
	char	**tab;
	char	*tmp[1024];
	FILE	*file_to_fileno;
	int		fd;
	int		i = 0;
	int		j = 0;

	file_to_fileno = fopen(file, "r");
	if (!file_to_fileno)
		return (NULL);

	fd = fileno(file_to_fileno);
	if (fd < 0)
	{
		fclose (file_to_fileno);
		return (NULL);
	}
	while (1)
	{
		str = get_next_line(fd);
		if (!str || i == 1024)
			break;
		tmp[i] = str;
		i++;
	}
	tmp[i] = NULL;
	fclose(file_to_fileno);

	tab = malloc(sizeof(char *) * (i + 1));
	if (!tab)
	{
		i = 0;
		while (tmp[i])
		{
			free (tmp[i]);
			i++;
		}
		return (NULL);
	}
	while (tmp[j])
	{
		tab[j] = tmp[j];
		j++;
	}
	tab[j] = NULL;
	return (tab);
}
