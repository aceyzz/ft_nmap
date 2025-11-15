/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strtrim.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cduffaut <marvin@42lausanne.ch>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/10/11 14:34:17 by cduffaut          #+#    #+#             */
/*   Updated: 2023/10/12 08:58:04 by csil             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdio.h>

/*
	Tant que c'est une lettre qui fait partie de set ==> ++
*/

int	is_trim(char c, const char *set)
{
	int	j;

	j = 0;
	while (set[j])
	{
		if ((char)set[j] == c)
			return (1);
		j++;
	}
	return (0);
}

char	*ft_strtrim(char const *s1, char const *set)
{
	size_t	min;
	size_t	max;
	size_t	len;
	char	*str;

	if (!s1)
		return (NULL);
	if (!set)
		return (ft_strdup(s1));
	min = 0;
	while (s1[min] && is_trim(s1[min], set) == 1)
		min++;
	max = ft_strlen(s1) - 1;
	while (max > min && is_trim(s1[max], set) == 1)
		max--;
	if (min > max)
		return (ft_strdup(""));
	len = max - min + 1;
	str = ft_substr(s1, min, len);
	if (!str)
		return (NULL);
	return (str);
}
/*
int	main(void)
{
	char const	*s = "1232C'è un21321 bello tempo123 !";
	printf ("%s\n", ft_strtrim("123123U", "123"));
	return (0);
}*/
