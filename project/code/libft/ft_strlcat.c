/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strlcat.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cduffaut <marvin@42lausanne.ch>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/10/11 14:32:44 by cduffaut          #+#    #+#             */
/*   Updated: 2023/10/12 16:06:42 by csil             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdio.h>

/*
	Si size <= len (dest)
		return (size + len (src)
	else
		copy_paste (src to dest)
			return (len(src) + len(dest);	
*/

size_t	ft_strlcat(char *dest, const char *src, size_t count)
{
	size_t	i;

	i = 0;
	if (!dest && count == 0)
		return (0);
	while (dest[i])
		i++;
	while (i + 1 < count && *src)
	{
		dest[i] = *src;
		i++;
		src++;
	}
	dest[i] = '\0';
	if (ft_strlen(dest) > count)
		return (ft_strlen(src) + count);
	else
		return (ft_strlen(dest) + ft_strlen(src));
}
/*
int	main(void)
{
	char 	dest[100] = "";
	char 	src[100] = "";
	size_t 	count = 0;

	printf ("fake = %zu\n", ft_strlcat(NULL, src, 0));
	printf ("vrai = %lu\n", strlcat(src, NULL, 0));
	return (0);
}*/
