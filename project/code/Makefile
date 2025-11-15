SRCS	= \
			program/ft_nmap.c program/parsing/parsing.c \
			program/exit/error_and_exit.c program/utils/utils.c \
			program/init/init.c program/utils/utils_parsing.c \
			gnl/get_next_line.c gnl/get_next_line_utils.c \
			program/execution/launch.c \
			program/execution/execution.c program/checksum/ft_checksum.c \
			program/execution/thread_scan.c program/utils/linked_list.c \
			program/parsing/scan.c program/parsing/help.c program/parsing/ip.c \
			program/parsing/ports.c program/parsing/speedup.c program/receive/receive.c \
			program/print_stats/print_stats.c program/print_stats/print_result.c
OBJS	= $(SRCS:.c=.o)
GCC		= gcc -Wall -Wextra -Werror -g
NAME	= ft_nmap
LIBFT	= libft/libft.a

all: $(LIBFT) $(NAME)

$(LIBFT):
	$(MAKE) -C libft

$(NAME): $(OBJS) $(LIBFT)
	$(GCC) -o $(NAME) $(OBJS) -Llibft -lft -lpcap -lpthread

.c.o:
	$(GCC) -c $< -o $@

clean:
	rm -f $(OBJS)
	$(MAKE) -C libft clean

fclean: clean
	rm -f $(NAME)
	$(MAKE) -C libft fclean

re: fclean all

leaks:
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./$(NAME) --ip 10.0.0.10 --speedup 250 

.PHONY: re fclean clean all leaks