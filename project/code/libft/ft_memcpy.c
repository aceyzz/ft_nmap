/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memcpy.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cduffaut <marvin@42lausanne.ch>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/10/11 14:29:47 by cduffaut          #+#    #+#             */
/*   Updated: 2023/10/11 14:29:49 by cduffaut         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdio.h>

void	*ft_memcpy(void *dest, const void *src, size_t n)
{
	char	*relais;
	char	*r_src;
	int		i;

	if (!dest && !src)
		return (NULL);
	r_src = (char *) src;
	relais = (char *) dest;
	i = 0;
	while (n > 0)
	{
		relais[i] = r_src[i];
		n--;
		i++;
	}
	return (dest);
}
/*
int	main(void)
{
	char	dest[100] = "M'sieur Clémenceau";
	char	src[100] = "Aux";
	ft_memcpy(dest, src, 10);
	printf ("%s\n", dest);
}*/
