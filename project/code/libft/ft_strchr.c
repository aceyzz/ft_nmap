/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strchr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cduffaut <marvin@42lausanne.ch>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/10/11 14:31:38 by cduffaut          #+#    #+#             */
/*   Updated: 2023/10/11 17:37:36 by csil             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdio.h>

char	*ft_strchr(const char *s, int c)
{
	char	*tmp;

	tmp = (char *)s;
	while (*tmp)
	{
		if (*tmp == (char)c)
			return (tmp);
		tmp++;
	}
	if (*tmp == (char)c)
		return (tmp);
	else
		return (NULL);
}
/*
int	main(void)
{
	char	s[100] = "Sono nel club con la mia gang";
	int	c = 'l';
	
	printf ("%s\n", ft_strchr("teste", 'e'));
	printf ("%s\n", strchr("teste", 'e'));
	return (0);
}*/
