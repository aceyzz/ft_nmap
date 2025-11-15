/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_atoi.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cduffaut <marvin@42lausanne.ch>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/10/11 14:24:04 by cduffaut          #+#    #+#             */
/*   Updated: 2023/10/11 14:24:07 by cduffaut         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdio.h>

int	ft_atoi(const char *nptr)
{
	int	minus;
	int	nbr;

	nbr = 0;
	minus = 1;
	while (*nptr && ((*nptr > 8 && *nptr < 14) || *nptr == 32))
	{
		nptr++;
	}
	if (*nptr == 45 || *nptr == 43)
	{
		if (*nptr == 45)
			minus = -1;
		nptr++;
	}
	while (*nptr >= '0' && *nptr <= '9')
	{
		nbr = (nbr * 10) + (*nptr - '0');
		nptr++;
	}
	return (nbr * minus);
}
/*
int	main(void)
{
	const char str[100] = " 	 	234";

	printf("faux = %d\n", ft_atoi(str));
	printf("vrai = %d\n", atoi(str));
	return (0);
}*/
