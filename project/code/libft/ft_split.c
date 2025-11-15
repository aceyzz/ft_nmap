/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_split.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cduffaut <marvin@42lausanne.ch>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/10/11 14:31:26 by cduffaut          #+#    #+#             */
/*   Updated: 2023/10/24 14:35:40 by cduffaut         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdio.h>

int	str_nbr(char const *s, char c)
{
	int	i;
	int	j;

	i = 0;
	j = 0;
	while (s[i])
	{
		while (s[i] && s[i] == c)
			i++;
		if (s[i] && s[i] != c)
			j++;
		while (s[i] && s[i] != c)
			i++;
	}
	return (j);
}

char	*cpypste(char const *s, int i, char c)
{
	char	*str;
	int		j;

	j = i;
	while (s[j] && s[j] != c)
		j++;
	str = malloc(sizeof(char) * (j - i + 1));
	if (!str)
		return (NULL);
	j = 0;
	while (s[i] && s[i] != c)
		str[j++] = s[i++];
	str[j] = '\0';
	return (str);
}

char	**free_split(char **tab)
{
	int		i;

	i = 0;
	while (tab[i])
	{
		free(tab[i]);
		i++;
	}
	free(tab);
	tab = NULL;
	return (tab);
}

char	**ft_split(char const *s, char c)
{
	char	**tab;
	int		i;
	int		j;

	i = 0;
	j = 0;
	tab = malloc(sizeof(char *) * (str_nbr(s, c) + 1));
	if (!tab)
		return (NULL);
	while (s[i])
	{
		while (s[i] && s[i] == c)
			i++;
		if (s[i] && s[i] != c)
		{
			tab[j++] = cpypste(s, i, c);
			if (tab[j - 1] == NULL)
				return (free_split(tab));
		}
		while (s[i] && s[i] != c)
			i++;
	}
	tab[j] = (NULL);
	return (tab);
}
/*
int	main(void)
{
	char const 	s[] = "     Gesticolo    Quando    Parlo   com'un   Verro ...?    ";
	char		c = ' ';

	ft_split(s, c);
	return (0);
}*/
