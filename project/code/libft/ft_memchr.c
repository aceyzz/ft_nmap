/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memchr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cduffaut <marvin@42lausanne.ch>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/10/11 14:29:08 by cduffaut          #+#    #+#             */
/*   Updated: 2023/10/11 14:29:17 by cduffaut         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdio.h>

void	*ft_memchr(const void *s, int c, size_t n)
{
	unsigned char	*relais;
	unsigned char	copy;
	size_t			i;

	i = 0;
	copy = (unsigned char) c;
	relais = (unsigned char *) s;
	while (i < n)
	{
		if (*relais == copy)
			return (relais);
		relais++;
		i++;
	}	
	return (0);
}
/*
int	main(void)
{
	unsigned char   s[100] = "You2pidoupidoudou";
	printf ("le fo   : %s\n", ft_memchr(s, '2', 4));
	printf ("le vrai : %s\n", memchr(s, '2', 4));
	return (0);
}*/
