/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memset.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cduffaut <marvin@42lausanne.ch>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/10/11 14:30:17 by cduffaut          #+#    #+#             */
/*   Updated: 2023/10/11 14:30:18 by cduffaut         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdio.h>

void	*ft_memset(void *s, int c, size_t n)
{
	unsigned char	*relais;

	relais = (unsigned char *) s;
	while (n > 0)
	{
		*relais = c;
		relais++;
		n--;
	}
	return (s);
}
/*
int main (void)
{
	char	s[100] = "Bientot au Cap entends moi bien";
	ft_memset(s, 'a', 10);
	printf ("%s\n", s);
	return (0);
}*/
