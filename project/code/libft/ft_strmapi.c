/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strmapi.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cduffaut <marvin@42lausanne.ch>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/10/11 14:33:20 by cduffaut          #+#    #+#             */
/*   Updated: 2023/10/11 14:39:18 by cduffaut         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdio.h>

/*
	Applique la fonction ’f’ à chaque caractère de la
	chaîne de caractères passée en argument pour créer
	une nouvelle chaîne de caractères (avec malloc(3))
	résultant des applications successives de ’f’.
*/

char	*ft_strmapi(char const *s, char (*f)(unsigned int, char))
{
	unsigned int	i;
	char			*relais;
	char			*cpy;

	relais = NULL;
	if (!s || !f)
		return (0);
	relais = malloc(sizeof(char) * (ft_strlen(s) + 1));
	if (!relais)
		return (0);
	i = 0;
	cpy = (char *)s;
	while (cpy[i])
	{
		relais[i] = f(i, cpy[i]);
		i++;
	}
	relais[i] = '\0';
	return (relais);
}
/*
int	main(void)
{
	char const *s = "prout";
	char (*f)(unsigned int, char) = NULL;

	ft_strmapi(s, f);
	return (0);
}*/
