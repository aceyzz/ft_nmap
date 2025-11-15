/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstclear_bonus.c                                :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cduffaut <marvin@42lausanne.ch>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/10/11 14:27:26 by cduffaut          #+#    #+#             */
/*   Updated: 2023/10/11 14:27:28 by cduffaut         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdio.h>

void	ft_lstclear(t_list **lst, void (*del)(void *))
{
	t_list	*tmp;
	t_list	*cpy;

	if (!lst || !del)
		return ;
	cpy = *lst;
	while (cpy)
	{
		tmp = cpy->next;
		del(cpy->content);
		free (cpy);
		cpy = tmp;
	}
	*lst = NULL;
}
/*
int	main(void)
{
	t_list **alst;

	alst = NULL;
	void *a = NULL;
	ft_lstclear(alst, a);
	return (0);
}*/
