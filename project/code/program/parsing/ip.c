#include "../../includes/ft_nmap.h"

extern struct s_bag *list;

/*********************** File IP option ***********************/

// Go deeper into the ipv4 format of the ip, as gettaddrinfo is not sufficient enough
static bool	ip_ipv4_deeper(char *str)
{
	char	**tab = NULL;
	bool	res = true;

	if (char_count(str, '.') != 3)
		return (false);
	tab = ft_split(str, '.');
	if (!tab_len(tab, 4))
		res = false;;
	if (!non_numeric(tab))
		res = false;
	if (!number_range(tab))
		res = false;
	free_tab(tab);
	return (res);
}

// It return the ip in format string (127.0.0.1)
// Or NULL if hostname is not valid
// If it's already an IPV4 format it just return the (same) value
char *get_ip_by_hostname(char *str)
{
	struct addrinfo	*res;
	char			ip_str[INET_ADDRSTRLEN];

	if (getaddrinfo(str, NULL, 0, &res))
		print_error_and_free_list ("Error: At least one IP/Hostname is not in an IPV4 format\n", 1);
	if (res->ai_family != AF_INET)
	{
		freeaddrinfo (res);
		print_error_and_free_list ("Error: At least one IP/Hostname is not in an IPV4 format\n", 0);
	}
	struct sockaddr_in 	*ipv4 = (struct sockaddr_in *)res->ai_addr;
	struct in_addr 		*addr = &(ipv4->sin_addr);

	// Convert the addr into a str
	inet_ntop(res->ai_family, addr, ip_str, sizeof ip_str);
	freeaddrinfo (res);
	char *final = ft_strdup(ip_str);
	if (!final)
		print_error_and_free_list ("Error: something went wrong with strdup function\n", 1);
	return (final);
}

// It checks if all the IPs/hostname in FILE are IPV4 or right format.
static void check_file_ips()
{
	int		i = 0;
	char	*res = NULL;

	while (list->ip_str[i])
	{
		res = get_ip_by_hostname(list->ip_str[i]);
		if (res)
		{
			free (list->ip_str[i]);
			list->ip_str[i] = res; // give the format ip "127.0.0.1" to ip_str if it was given hostname at first
		}
		else
			print_error_and_free_list("Error: Get Host By Hostname went wrong.\nMaybe an IP/ host is not in the correct IPV4 format.\n", 0);
		if (ip_ipv4_deeper(list->ip_str[i]) == false)
			print_error_and_free_list("Error: One ip adress at least is not in the IPV4 format in the file.\n", 0);
		i++;		
	}
}

void check_file_option(char *fname)
{
    FILE *file;

	if (list->file == true)
		print_error_and_free_list("Error : you cannot have two times the same option FILE.\n", 0);
    if (!(file = fopen(fname, "r")))
    {
		printf ("Error: could not open the file %s\n", fname);
        print_error_and_free_list("", 0);
    }
	fclose(file);
	if (list->ip_str)
		print_error_and_free_list("Error: the option --ip and --file cannot be both activated.\n", 0);	
	list->ip_str = main_gnl(fname);
	if (!list->ip_str || !list->ip_str[0])
		print_error_and_free_list("Error: the reading of the file (--file) failed or is empty.\nStopping the program.\n", 0);
	check_file_ips();
	list->file = true;
}

/*********************** Single IP option ***********************/

void	check_ip_option(char *str)
{
	if (list->file == true)
		print_error_and_free_list("Error : you cannot have --ip and --file both activated.\n", 0);

	if (list->ip == true)
		print_error_and_free_list("Error : you cannot have two times the same option IP.\n", 0);
	// (!) here str is allocated
	list->ip_str = ft_split(str, ',');

	char 	*tmp;
	int		 i = 0;

	while (list->ip_str[i])
	{
		tmp = get_ip_by_hostname(list->ip_str[i]);
		if (ip_ipv4_deeper(tmp) == false)
		{
			free (tmp);
			print_error_and_free_list("Error: the IP in input is not in the right format (IPV4).\n", 1);
		}
		free (list->ip_str[i]);
		list->ip_str[i] = tmp;
		i++;
	}
	if (!list->ip_str)
		print_error_and_free_list("Error: there is no valid IPV4 IPs in input.\n", 1);
	list->ip = true;
}

/*********************** Get final format struct IP to stock all the data ***********************/

static t_ip create_ip_node(char *hostname)
{
    // getting the address info of the host with the hostname in input
    struct addrinfo *res;
	struct addrinfo hints;

	ft_memset(&hints, 0, sizeof(struct addrinfo));

	hints.ai_flags = AI_CANONNAME;
	hints.ai_family = AF_INET;

    if (getaddrinfo(hostname, NULL, &hints, &res) != 0)
        print_error_and_free_list("Error: something went wrong with getaddrinfo()\nClosing the program...\n", 1);

    t_ip ip;
	ft_memset(&ip, 0, sizeof(struct s_ip));
	ip.addrlen = res->ai_addrlen;
    
	// copying the address bytes by bytes to avoid loss of information
    ft_memcpy(&ip.addr, res->ai_addr, res->ai_addrlen);

    // save the ip of the host (string format)
    char ip_str[INET_ADDRSTRLEN] = {0};
    inet_ntop(res->ai_family, &ip.addr.ipv4.sin_addr, ip_str, sizeof(ip_str));
    if (ft_strcmp(res->ai_canonname, ip_str) != 0) // combining hostname and ip str format if both are differents and stock it into ip.hostname.
		snprintf(ip.hostname, sizeof(ip.hostname), "%s(%s)", res->ai_canonname, ip_str);
    else
        snprintf(ip.hostname, sizeof(ip.hostname), "%s", ip_str);

    freeaddrinfo(res);
    return ip;
}

static void add_node_to_list(t_ip *addr)
{
    t_ip *current = list->res;
    t_ip *new_node = NULL;

    for (; current; current = current->next)
    {
        if (ft_memcmp(&current->addr.ipv4.sin_addr, &addr->addr.ipv4.sin_addr, sizeof(struct in_addr)) == 0)
        {
            printf("(!)Info: a hostname has been found in duplicate :%s. Ignoring it...\n", addr->hostname);
            return;
        }
        if (!current->next)
            break;
    }

    new_node = ft_calloc(1, sizeof(t_ip));
    if (!new_node)
        print_error_and_free_list("Error: ft_calloc() failed.Stopping the program...\n", 1);
    ft_memcpy(new_node, addr, sizeof(t_ip));
    new_node->next = NULL;

    if (current == NULL)
        list->res = new_node;
    else
        current->next = new_node;
}

// this function go through the IP parsed tab and create a linked list with important data for all IPs asked
void	add_ip_node_to_list()
{
	int		i = 0;
	t_ip	*tmp;

	if (!list || !list->ip_str)
	{
		print_error_and_free_list("Error : list or ip_str not initialized\n", 0);
		return;
	}

	if (ft_strlen_tab(list->ip_str) > MAX_IPS)
		print_error_and_free_list("Error: too many IPs (max IPs supported: 42)\n", 0);
	while (list->ip_str[i])
	{
		tmp = (t_ip *)malloc(sizeof(t_ip));
		if (!tmp)
			print_error_and_free_list("Error: malloc() failed for tmp IP node.\n", 1);
		*tmp = create_ip_node(list->ip_str[i]);
		add_node_to_list(tmp);
		free(tmp);
		i++;
	}
}