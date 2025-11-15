/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   get_next_line.h                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: csil <csil@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/10/16 09:59:19 by csil              #+#    #+#             */
/*   Updated: 2023/10/16 22:01:07 by csil             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef GET_NEXT_LINE_H
# define GET_NEXT_LINE_H

# ifndef BUFFER_SIZE
#  define BUFFER_SIZE 10
# endif

# include <stdlib.h>
# include <unistd.h>
# include <fcntl.h>

char	*get_next_line(int fd);
char	*create_stock(char *stock, int fd);
char	*create_line(char *stock);
char	*clean_stock(char *stock);
char	*free_all(char *str);
int		check_n(char *str);
char	*ft_strjoin_gnl(char *stock, char *tmp);
int		ft_strlen_gnl(char *str);
char	*ft_strndup_gnl(char *stock, int i);
char	*ft_calloc_gnl(size_t count, size_t size);
char	**main_gnl(char *file);

#endif
