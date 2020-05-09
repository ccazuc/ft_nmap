# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: ccazuc <marvin@42.fr>                      +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2017/11/07 11:15:45 by ccazuc            #+#    #+#              #
#    Updated: 2019/01/24 10:39:10 by kehuang          ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

NAME = libft.a

CC = gcc

CFLAGS = -Wall -Wextra -Werror

SRCS_PATH = srcs/

INCLUDES_PATH = includes/

SRCS_NAME = ft_atoi.c \
			ft_bzero.c \
			ft_isalnum.c \
			ft_isalpha.c \
			ft_isascii.c \
			ft_isdigit.c \
			ft_isprint.c \
			ft_isspace.c \
			ft_itoa.c \
			ft_memalloc.c \
			ft_memccpy.c \
			ft_memchr.c \
			ft_memcmp.c \
			ft_memcpy.c \
			ft_memdel.c \
			ft_memmove.c \
			ft_memset.c \
			ft_putchar.c \
			ft_putchar_fd.c \
			ft_putendl.c \
			ft_putendl_fd.c \
			ft_putnbr.c \
			ft_putnbr_fd.c \
			ft_putstr.c \
			ft_putstr_fd.c \
			ft_strcat.c \
			ft_strchr.c \
			ft_strclr.c \
			ft_strcmp.c \
			ft_strcpy.c \
			ft_strdel.c \
			ft_strdup.c \
			ft_strequ.c \
			ft_striter.c \
			ft_striteri.c \
			ft_strjoin.c \
			ft_strlcat.c \
			ft_strlen.c \
			ft_strmap.c \
			ft_strmapi.c \
			ft_strncat.c \
			ft_strncmp.c \
			ft_strncpy.c \
			ft_strnequ.c \
			ft_strnew.c \
			ft_strnstr.c \
			ft_strrchr.c \
			ft_strsplit.c \
			ft_strstr.c \
			ft_strsub.c \
			ft_strtrim.c \
			ft_tolower.c \
			ft_toupper.c \
			ft_lstnew.c \
			ft_lstdelone.c \
			ft_lstdel.c \
			ft_lstadd.c \
			ft_lstiter.c \
			ft_lstmap.c \
			ft_strcount.c \
			ft_str_isdigit.c \
			ft_exit.c \
			ft_strjoin_free12.c \
			ft_strsub_start.c \
			ft_strjoin_free1.c \
			ft_todegrees.c \
			ft_toradians.c \
			ft_math_fabs.c \
			ft_math_dabs.c \
			ft_math_max.c \
			ft_math_abs.c \
			ft_isblank.c \
			ft_isspace.c \
			ft_isxdigit.c \
			ft_putstr_array.c \
			ft_str_isalpha.c \
			ft_array_len.c \
			ft_strcmp_ignrcase.c \

SRCS = $(addprefix $(SRCS_PATH), $SRCS_NAME))

OBJS_PATH = obj/

OBJS_NAME = $(SRCS_NAME:.c=.o)

OBJS = $(addprefix $(OBJS_PATH), $(OBJS_NAME))

all: $(OBJS_PATH) $(NAME)

$(NAME): $(OBJS)
	@echo " - Making $(NAME)"
	@ar -rc $(NAME) $(OBJS)
	@ranlib $(NAME)

$(OBJS_PATH)%.o: $(SRCS_PATH)%.c $(INCLUDES_PATH)libft.h
	@echo " - Compiling $<"
	@$(CC) $(CFLAGS) -o $@ -c $< -I$(INCLUDES_PATH)

$(OBJS_PATH):
	@mkdir -p $(OBJS_PATH)

clean:
	@echo " - Cleaning objs"
	@rm -f $(OBJS)
	@rm -rf $(OBJS_PATH)

fclean: clean
	@echo " - Cleaning executable"
	@rm -f $(NAME)

re:
	@$(MAKE) fclean
	@$(MAKE) all

.PHONY: all clean fclean re $(OBJS_PATH)
