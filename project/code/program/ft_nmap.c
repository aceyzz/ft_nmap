#include "../includes/ft_nmap.h"

struct s_bag *list;

int	main(int ac, char **av)
{
	struct timeval start;
	list = malloc(sizeof(t_bag));
	if (!list)
		print_error_and_exit("Error: something went wrong with memory allocation of the list.\n", 1);
	ft_memset(list, 0, (sizeof(t_bag)));
	if (pthread_mutex_init(&list->state_mutex, NULL) != 0)
		print_error_and_exit("Error: mutex initialization failed.\n", 1);
	ft_parsing(ac, av);
    
    gettimeofday(&start, NULL);
	
	send_requests();
	signal(SIGALRM, ft_timeout);
	alarm(15); // set the timeout to 15 seconds to avoid infinite loop

	while (!list->stop_nmap) // while we've not recover all the res or if no answers from 15sec it stops the listening
		pcap_dispatch(list->handle, -1, ft_receive_pckt, NULL); // -1 so it's listening in continue

	pcap_close(list->handle);
	ft_display_stats(start);
	pthread_mutex_destroy(&list->state_mutex);
	free_list();
	return (0);
}