/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstadd_back_bonus.c                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cduffaut <marvin@42lausanne.ch>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/10/11 14:26:58 by cduffaut          #+#    #+#             */
/*   Updated: 2023/10/11 14:27:00 by cduffaut         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdio.h>

/* Ajoute l’élément ’new’ à la fin de la liste. */

void	ft_lstadd_back(t_list **lst, t_list *new)
{
	t_list	*tmp;

	if (!new)
		return ;
	if (!(*lst))
	{
		(*lst) = new;
		return ;
	}
	tmp = (*lst);
	while (tmp->next)
	{
		tmp = tmp->next;
	}
	tmp->next = new;
}
/*
int	main(void)
{
	t_list	**li;
	t_list	*new;

	li = NULL;
	new = NULL;
	ft_lstadd_back(li, new);
	return (0);
}*/
