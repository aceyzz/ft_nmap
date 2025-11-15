/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strnstr.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cduffaut <marvin@42lausanne.ch>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/10/11 14:33:46 by cduffaut          #+#    #+#             */
/*   Updated: 2023/10/12 16:11:36 by csil             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdio.h>

/*
s1 = The string to be searched

s2 = The string to search for

len = the maximum number of characters to search
*/

int	is_valid(char *haystack, size_t i, const char *needle, size_t len)
{
	int	j;

	j = 0;
	while (haystack[i] == needle[j] && needle[j] && haystack[i] && i < len)
	{
		i++;
		j++;
	}
	if (needle[j] == '\0')
		return (1);
	else
		return (0);
}

char	*ft_strnstr(const char *s1, const char *s2, size_t len)
{
	char	*temp;
	size_t	i;

	temp = (char *) s1;
	if (!s1 && len == 0)
		return (NULL);
	if ((char)s2[0] == '\0')
		return ((char *)s1);
	i = 0;
	while (temp[i] && i < len)
	{
		if (temp[i] == (char)s2[0])
			if (is_valid(temp, i, (char *)s2, len) == 1)
				return (&temp[i]);
		temp++;
		len--;
	}
	return (NULL);
}
/*
int	main(void)
{
	const char	haystack[100] = "la befana viene di notte ventuno ma coragioso";
	const char	needle[100] = "vent\0un";
	size_t		len = 6;

	printf ("faux = %s\n", ft_strnstr(NULL, "okay_ets", 0));
	printf ("vrai = %s\n", strnstr(NULL, "okay_ets", 0));
	return (0);
}*/
