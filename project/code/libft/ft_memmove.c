/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memmove.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cduffaut <marvin@42lausanne.ch>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/10/11 14:30:04 by cduffaut          #+#    #+#             */
/*   Updated: 2023/10/11 23:45:27 by csil             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdio.h>

void	*ft_memmove(void *dest, const void *src, size_t n)
{
	char	*source;
	size_t	i;

	source = (char *)src;
	i = 0;
	if ((char *)dest == source)
		return (dest);
	else if ((char *)dest > source)
	{
		while (n-- > 0)
			((char *)dest)[n] = source[n];
	}
	else
	{
		while (i < n)
		{
			((char *)dest)[i] = source[i];
			i++;
		}	
	}
	return (dest);
}
/*
int	main(void)
{
	char	src[58] = "La vie c'est magik ???";
	ft_memmove(src , src, sizeof(char) * 4);
	//memmove (src, src, sizeof(char) * 4);
	printf ("%s\n", src);
}*/
