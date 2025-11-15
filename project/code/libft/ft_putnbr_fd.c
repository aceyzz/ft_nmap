/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_putnbr_fd.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cduffaut <marvin@42lausanne.ch>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/10/11 14:31:05 by cduffaut          #+#    #+#             */
/*   Updated: 2023/10/11 17:22:31 by csil             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdio.h>

void	ft_putnbr_fd(int n, int fd)
{
	if (n == 0)
	{
		ft_putchar_fd('0', fd);
		return ;
	}
	else if (n == -2147483648)
	{
		ft_putstr_fd("-2147483648", fd);
		return ;
	}
	if (n < 0)
	{
		ft_putchar_fd('-', fd);
		n = -n;
	}
	if (n < 10)
		ft_putchar_fd((n + 48), fd);
	else
	{
		ft_putnbr_fd((n / 10), fd);
		ft_putnbr_fd((n % 10), fd);
	}
}
/*
int	main(void)
{
	ft_putnbr_fd(0, 0);
	ft_putnbr_fd(-2147483648, 0);
	ft_putnbr_fd(-1807, 0);
	ft_putnbr_fd(2147483647, 0);
	ft_putnbr_fd(-111, 0);
	ft_putnbr_fd(1234, 0);
	ft_putnbr_fd(-9876, 0);
	return (0);
}*/
