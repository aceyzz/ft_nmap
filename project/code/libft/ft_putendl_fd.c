/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_putendl_fd.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cduffaut <marvin@42lausanne.ch>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/10/11 14:30:49 by cduffaut          #+#    #+#             */
/*   Updated: 2023/10/11 14:30:51 by cduffaut         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdio.h>

void	ft_putendl_fd(char *s, int fd)
{
	if (!s)
		return ;
	while (*s)
	{
		write (fd, &*s, 1);
		s++;
	}
	write (fd, "\n", 1);
}
/*
int	main(void)
{
	char	s[] = "Together that's how it's must be to live without u";
	ft_putendl_fd(s, 9);
	return (0);
}*/
