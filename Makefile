NAME = ft_nmap

CFLAGS = -Wall -Wextra -g

CC = gcc

INCLUDES_PATH = include/

SRCS_PATH = src/

SRCS_NAME = main.c \
			parse_args.c \
			print.c \
			thread.c \
			create_socket.c \
			resolve_host.c \
			get_time.c \
			send_scan.c \
			forge_headers.c \
			
SRCS = $(addprefix $(SRCS_PATH), $(SRCS_NAME))

OBJS_PATH = obj/

OBJS_NAME = $(SRCS_NAME:.c=.o)

OBJS = $(addprefix $(OBJS_PATH), $(OBJS_NAME))

LIBRARY = -L libft -lft -lpthread -lm

all: odir $(NAME)

$(NAME): $(OBJS)
	@make -C libft
	@echo " - Making $(NAME)"
	@$(CC) $(CFLAGS) -o $(NAME) $^ $(LIBRARY)

$(OBJS_PATH)%.o: $(SRCS_PATH)%.c
	@echo " - Compiling $<"
	@$(CC) $(CFLAGS) -o $@ -c $< -I$(INCLUDES_PATH)

odir:
	@mkdir -p $(OBJS_PATH)

clean:
	@make clean -C libft
	@echo " - Clearing objects files"
	@rm -f $(OBJS)
	@rm -rf $(OBJS_PATH)

fclean: clean
	@make fclean -C libft
	@echo " - Clearing executable file"
	@rm -f $(NAME)

re:
	@$(MAKE) fclean
	@$(MAKE) all

.PHONY: all clean fclean re odir
