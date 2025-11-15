/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstnew_bonus.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cduffaut <marvin@42lausanne.ch>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/10/11 14:28:37 by cduffaut          #+#    #+#             */
/*   Updated: 2023/10/11 14:28:38 by cduffaut         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

/*
	Alloue (avec malloc(3)) et renvoie un nouvel
	élément. La variable membre ’content’ est
	initialisée à l’aide de la valeur du paramètre
	’content’. La variable ’next’ est initialisée à
	NULL.
*/

t_list	*ft_lstnew(void *content)
{
	t_list	*new;

	new = malloc(sizeof(t_list));
	if (!new)
		return (NULL);
	new->next = NULL;
	new->content = content;
	return (new);
}
/*
int	main(void)
{
	ft_lstnew("hola_todos");
	return (0);
}*/
