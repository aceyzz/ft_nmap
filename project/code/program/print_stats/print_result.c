#include "../../includes/ft_nmap.h"

extern struct s_bag *list;

static char    *get_service_name(int port)
{
    struct servent  *service;

    service = getservbyport(htons(port), "tcp");
    if (service)
        return (service->s_name);
    
    service = getservbyport(htons(port), "udp");
    if (service)
        return (service->s_name);
    
    return NULL;
}

char    *scan_in_str(int scan)
{
    switch (scan)
    {
    case SYN:
        return ("SYN");
    case NUL:
        return ("NULL");
    case FIN:
        return ("FIN");
    case XMAS:
        return ("XMAS");
    case ACK:
        return ("ACK");
    case UDP:
        return ("UDP");
    default:
        return ("UNKNOWN");
    }
    return ("UNKNOWN");
}

char    *state_in_str(int state)
{
    switch (state)
    {
    case CLOSED:
        return "Closed";
    case OPEN:
        return "Open";
    case FILTERED:
        return "Filtered";
    case UNFILTERED:
        return "Unfiltered";
    case OPENFILTERED:
        return "Open|Filtered";
    default:
        return "Unknown";
    }
    return "Unknown";
}

static void     print_header()
{
    printf ("%-8s%-20s%-50s%-15s\n", "Port", "Service Name", "Results", "Conclusion");
    printf ("-----------------------------------------------------------------------------------------------------------------------\n");  
}

// check if one of the scans result for the port is: open
static bool     is_open(t_ip *ip, int port)
{
    for (int scan = 1; scan < TOTAL_TYPE; scan++)
    {
        if (ip->state[scan][port] == OPEN)
            return (true);
    }
    return (false);
}

static void     print_ports_state(t_ip *ip, int port, char *state)
{
    int printed = 0;
    char current_line[100] = {0};
    int current_pos = 0;
    bool is_first_line = true;

    for (int scan = 1; scan < TOTAL_TYPE; scan++)
    {
        if (list->info_scan[scan])
        {
            char scan_str[50];
            snprintf(scan_str, sizeof(scan_str), "%s(%s) ", scan_in_str(scan), state_in_str(ip->state[scan][port]));
            int scan_len = strlen(scan_str);
            
            // Check if we need to wrap (after 3 or 5 items)
            if (printed > 0 && (printed == 3 || printed == 5))
            {
                // Pad current line to 50 chars and print with proper indentation
                while (current_pos < 50)
                {
                    current_line[current_pos] = ' ';
                    current_pos++;
                }
                current_line[current_pos] = '\0';
                
                if (is_first_line)
                {
                    printf("%s\n", current_line);
                    is_first_line = false;
                }
                else
                    printf("%-28s%s\n", "", current_line);
                
                // Reset for next line with indentation
                ft_memset(current_line, 0, sizeof(current_line));
                current_pos = 0;
            }
            
            // Add scan result to current line
            if (current_pos + scan_len < 100)
            {
                ft_strcat(current_line, scan_str);
                current_pos += scan_len;
            }
            printed++;
        }
    }
    
    // Pad the last line to 50 characters
    while (current_pos < 50)
    {
        current_line[current_pos] = ' ';
        current_pos++;
    }
    current_line[current_pos] = '\0';
    
    // Print last line with proper indentation if needed
    if (is_first_line)
        printf("%-50s%s\n", current_line, state);
    else
        printf("%-28s%-50s%s\n", "", current_line, state);
}

static void     display_close_stat(t_ip *ip, int port, bool first)
{
    char    *service_name = get_service_name(port);

    if (!service_name)
        service_name = "Unassigned";
    if (first)
    {
        printf ("Closed/Filtered/Unfiltered ports:\n");
        print_header();
    }
    printf("%-8d%-20s", port, service_name);
    print_ports_state(ip, port, "Closed");
}

static void     print_close(t_ip *ip)
{
    bool    first = true;

    for (int port = 0; port < 65536; port++) // go through all the ports
    {
        if (list->info_port[port] == true) // if port is true
        {
            // print it in the close section if open came to be false
            if (is_open(ip, port) == false)
            {
                display_close_stat(ip, port, first);
                first = false;
            }
        }
    }
    printf ("\n");
}

static void     display_open_stat(t_ip *ip, int port, bool first)
{
    char    *service_name = get_service_name(port);
    if (!service_name)
        service_name = "Unassigned";
    if (first)
    {
        printf ("Open ports:\n");
        print_header();
    }
    printf("%-8d%-20s", port, service_name);
    print_ports_state(ip, port, "Open");
}

static void    print_open(t_ip *ip)
{
    bool    first = true;
    printf ("IP address: %s\n", ip->hostname);
    for (int port = 0; port < 65536; port++) // go through all the ports
    {
        if (list->info_port[port] == true) // if port is true
        {
            // print it in the open section if open came to be true
            if (is_open(ip, port) == true)
            {
                display_open_stat(ip, port, first);
                first = false;
            }
        }
    }
    printf ("\n");
}

// print in the right side the port and its result in function of if it is open or not 
static void print_by_state(t_ip *ip)
{
    print_open(ip);
    print_close(ip);
}

// send to the dispach function all the ips scannned
void    print_result()
{
    // go through all the ips scanned
    for (t_ip *tmp = list->res; tmp; tmp = tmp->next)
        print_by_state(tmp);
}
