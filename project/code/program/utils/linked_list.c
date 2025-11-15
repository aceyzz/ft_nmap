#include "../../includes/ft_nmap.h"

extern struct s_bag *list;

struct s_ip	*ptr_last_node(struct s_ip *li)
{
	if (!li)
		return (NULL);
	while (li->next)
	{
		li = li->next;
	}
	return (li);
}

void	add_end(struct s_ip **li, struct s_ip *new_node)
{
	struct s_ip	*tmp;
	if (!(*li))
	{
		*li = new_node;
		return ;
	}
	tmp = ptr_last_node(*li);
	tmp->next = new_node;
}

