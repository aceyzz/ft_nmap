/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstdelone_bonus.c                               :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cduffaut <marvin@42lausanne.ch>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/10/11 14:27:37 by cduffaut          #+#    #+#             */
/*   Updated: 2023/10/11 14:27:39 by cduffaut         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdio.h>

/* 
	/!!!!!\ Lui a recheck avec le sujet avant de push 
*/

void	ft_lstdelone(t_list *lst, void (*del)(void *))
{
	if (!lst || !del)
		return ;
	(*del)(lst->content);
	free (lst);
	lst = NULL;
}
/*
int	main(void)
{
	t_list *alst;

	alst = NULL;
	void *a = NULL;
	ft_lstdelone(alst, a);
	return (0);
}*/
