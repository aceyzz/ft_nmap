/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_itoa.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cduffaut <marvin@42lausanne.ch>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/10/11 14:26:33 by cduffaut          #+#    #+#             */
/*   Updated: 2023/10/12 00:14:57 by csil             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdio.h>

int	ft_len(long n)
{
	int	i;

	i = 0;
	if (n == 0)
		return (1);
	while (n > 0)
	{
		i++;
		n /= 10;
	}
	return (i);
}

char	*crea_nbr(long n, int neg)
{
	char	*temp;
	int		len;

	len = ft_len(n) + neg;
	temp = malloc(sizeof(char) * (len + 1));
	if (!temp)
		return (NULL);
	if (neg == 1)
		temp[0] = '-';
	temp[len] = '\0';
	len -= 1;
	if (n == 0)
		temp[len] = '0';
	while (n > 0)
	{
		temp[len] = ((n % 10) + 48);
		n /= 10;
		len -= 1;
	}
	return (temp);
}

char	*ft_itoa(int n)
{
	int		neg;
	long	nbr;
	char	*str;

	neg = 0;
	nbr = 0;
	if (n == -2147483648)
	{
		nbr = 2147483648;
		neg = 1;
	}
	else if (n < 0)
	{
		neg = 1;
		nbr = -n;
	}
	else
		nbr = n;
	str = crea_nbr(nbr, neg);
	return (str);
}
/*
int	main(void)
{
	//printf ("%s\n", ft_itoa(0));
	//printf ("%s\n", ft_itoa(2147483647));
	printf ("%s\n", ft_itoa(-2147483648));
	//printf ("%s\n", ft_itoa(-111));
	//printf ("%s\n", ft_itoa(777));
	//printf ("%s\n", ft_itoa(-2145654));
	//printf ("%s\n", ft_itoa(93048274));
	return (0);
}*/
