#include "../../includes/ft_nmap.h"

extern struct s_bag *list;

static size_t ft_strncat(char *dest, const char *src, size_t n)
{
	size_t	dest_len = ft_strlen(dest);
	size_t	i;

	i = 0;
	while (src[i] && i < n)
	{
		dest[dest_len + i] = src[i];
		i++;
	}
	dest[dest_len + i] = '\0';
	return (dest_len + i);
}

static void	check_options(int ac, char **av)
{
	int	i = 1;
	int test = 0;
	
	while (i < ac)
	{
		test = (i % 2); 
		if (test)
		{
			if (ft_strcmp(av[i], "--ports") && ft_strcmp(av[i], "--ip") && ft_strcmp(av[i], "--file") && ft_strcmp(av[i], "--speedup") && ft_strcmp(av[i], "--scan"))
			{
				printf ("Error: option unknown: %s\n", av[i]);
				spread_help_option(); 
			}
		}
		i++;
	}
}

// Check if all the mandatory options has been sended in input
static void	check_mandatory_options()
{
	if (list->ip == false && list->file == false)
		print_error_and_free_list("Error: No target ip has been given in input.\n", 0);
	if (list->ports_range == false && list->ports_indiv == false)
	{
		list->ports_range = true;
		list->port_from = 1;
		list->port_to = 1024;
		list->count_ports = 1024;
	}
	if (list->scan == false)
	{
		list->scans.all = true;
		list->count_scans = 6;
	}
}

// Finds all the names of interfaces network, and we just get one to fulfill pcap funcs
static void get_ip_src()
{
    struct ifaddrs *ifaddr;
	struct ifaddrs *tmp;

    if (getifaddrs(&ifaddr) < 0)
		print_error_and_free_list("Error during the execution of getifaddrs function\n", 0);

	tmp = ifaddr;
    while (tmp != NULL)
	{
        if ((tmp->ifa_flags & IFF_BROADCAST) && tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET) // ifa_addr always exists if IFF_BROADCAST is set (we dont need to check if it is NULL)
        {
            // storing the interface address
            ft_memcpy(&list->ip_src, tmp->ifa_addr, sizeof(struct sockaddr_in));
			break;
        }
		tmp = tmp->ifa_next;
	}
	if (tmp == NULL)
		print_error_and_free_list("Error: no network interface founded\n", 0);
	else
	{
		char tmp2[INET_ADDRSTRLEN] = {0};
		inet_ntop(AF_INET , (void *)&list->ip_src.sin_addr, tmp2, sizeof(tmp2));
		ft_strcpy(list->ip_str_src, tmp2);
	}
    freeifaddrs(ifaddr);
}

// Initialisation packet listener
void	init_pcap()
{
	char 	filter[BUFSIZ] = {0};
	struct 	bpf_program fp = {0};
	int		i = 0;
	
	list->handle = pcap_open_live(NULL, BUFSIZ, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL);
	if (!list->handle)
		print_error_and_free_list("Error: pcap_open_live() failed. Could not open network interface.\n", 1);

    while (list->ip_str[i])
    {
        ft_strncat(filter, "host ", 5);
        ft_strncat(filter, list->ip_str[i], ft_strlen(list->ip_str[i]));
		i++;
        if (list->ip_str[i])
            ft_strncat(filter, " or ", 4);
    }
	// (bpf_program) compiled filter in a readable pcap format
	if (pcap_compile(list->handle, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) == -1)
		print_error_and_free_list("Error: pcap_compile() failed. Could not compile filter.\n", 1);
	// set the filter to the listening session
	if (pcap_setfilter(list->handle, &fp) == -1)
		print_error_and_free_list("Error: pcap_setfilter() failed. Could not set the filter.\n", 1);
	if (fp.bf_insns)
		free(fp.bf_insns);
}

static void ports_and_type_asked_into_global_list()
{
    for (int port = 0; port < RANGE_PORT; port++)
    {
        if (port_asked(port))
            list->info_port[port] = true;
        else
            list->info_port[port] = false;
    }

    for (int i = 1; i < TOTAL_TYPE; i++)
    {
        if (is_scan_asked(i) == true)
            list->info_scan[i] = true;
        else
            list->info_scan[i] = false;
    }
}

void	ft_parsing(int ac, char **av)
{
	int		i = 1;

	if(ac == 1)
		print_error_and_free_list("Error: You do not have put the mandatory arguments.\nFor more information please check the --help option.\n", 0);
	else if (geteuid() != 0)
		print_error_and_free_list("Error: You're not in root mode.\nThis program only works with root privileged\n", 0);
	check_help_option(ac, av);
	check_options(ac, av);

	while (i < ac)
	{
		if (!ft_strcmp(av[i], "--scan") && i < (ac - 1))
			check_scan_option(av[i + 1]);
		else if (!ft_strcmp(av[i], "--ip") && i < (ac - 1))
			check_ip_option(av[i + 1]);
		else if (!ft_strcmp(av[i], "--ports") && i < (ac - 1))
			check_ports_option(av[i + 1]);
		else if (!ft_strcmp(av[i], "--speedup") && i < (ac - 1))
			check_speedup_option(av[i + 1]);
		else if (!ft_strcmp(av[i], "--file") && i < (ac - 1))
			check_file_option(av[i + 1]);
		else if (i == (ac - 1) && (!ft_strcmp(av[i], "--ports") || !ft_strcmp(av[i], "--ip") || !ft_strcmp(av[i], "--file") || !ft_strcmp(av[i], "--speedup") || !ft_strcmp(av[i], "--scan")))
		{
			printf ("Error: last argument does not have options\n");
			spread_help_option();
		}
		i++;
	}
	if (list->ip == true && list->file == true)
		print_error_and_free_list("Error: You cannot do --ip and --file in the same execution\n", 0);
	check_mandatory_options();
	get_ip_src();
	add_ip_node_to_list();
	ports_and_type_asked_into_global_list();
	init_pcap();
}