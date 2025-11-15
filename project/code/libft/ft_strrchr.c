/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strrchr.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cduffaut <marvin@42lausanne.ch>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/10/11 14:33:58 by cduffaut          #+#    #+#             */
/*   Updated: 2023/10/11 23:40:34 by csil             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdio.h>

char	*ft_strrchr(const char *s, int c)
{
	size_t	i;
	char	*tmp;

	tmp = (char *)s;
	i = ft_strlen(s);
	while (i > 0 && tmp[i] != (char)c)
	{
		i--;
	}
	if (tmp[i] == (char)c)
		return (&tmp[i]);
	else
		return (NULL);
}
/*
int	main(void)
{
	const 	char s[100] = "Spaghetti Mafia Mandolino";
	//const 	char *s = NULL;
	int	c = 32;

	printf ("%s\n", ft_strrchr(s, c));
	printf ("%s\n", strrchr(s, c));
	return (0);
}*/
