/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strjoin.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cduffaut <marvin@42lausanne.ch>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/10/11 14:32:23 by cduffaut          #+#    #+#             */
/*   Updated: 2023/10/11 14:38:48 by cduffaut         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdio.h>

/*Allocates (with malloc(3)) and returns a “fresh” string end- ing with ’\0’, 
result of the concatenation of s1 and s2. 
If the allocation fails the function returns NULL.*/

char	*ft_strjoin(char const *s1, char const *s2)
{
	char	*str1;
	char	*str2;
	char	*str;
	int		i;

	i = 0;
	str1 = (char *)s1;
	str2 = (char *)s2;
	if (!s1)
		return (str2);
	else if (!s2)
		return (str1);
	str = malloc(sizeof(char) * (ft_strlen(s1) + ft_strlen(s2) + 1));
	if (!str)
		return (NULL);
	while (str1[i])
	{
		str[i] = str1[i];
		i++;
	}
	while (*str2)
		str[i++] = *str2++;
	str[i] = '\0';
	return (str);
}
/*
int	main(void)
{
	char	s1[] = "Tu te fais brancher par Alyssa, Zara, ";
	char	s2[] = "je l'enmène faire des courses chez Zara";
	printf ("%s\n", ft_strjoin(s1, s2));
	return (0);
}*/
