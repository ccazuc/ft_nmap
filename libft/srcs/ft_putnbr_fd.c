/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_putnbr_fd.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ccazuc <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/07 10:54:52 by ccazuc            #+#    #+#             */
/*   Updated: 2017/11/07 16:58:59 by ccazuc           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static void		print_min_value(int fd)
{
	ft_putchar_fd('-', fd);
	ft_putchar_fd('2', fd);
	ft_putchar_fd('1', fd);
	ft_putchar_fd('4', fd);
	ft_putchar_fd('7', fd);
	ft_putchar_fd('4', fd);
	ft_putchar_fd('8', fd);
	ft_putchar_fd('3', fd);
	ft_putchar_fd('6', fd);
	ft_putchar_fd('4', fd);
	ft_putchar_fd('8', fd);
}

void			ft_putnbr_fd(int n, int fd)
{
	int		tmp;
	int		length;

	if (n == -2147483648)
	{
		print_min_value(fd);
		return ;
	}
	length = 1;
	if (n < 0)
	{
		ft_putchar_fd('-', fd);
		n = -n;
	}
	tmp = n;
	while ((tmp = (tmp / 10)) > 0)
		length *= 10;
	tmp = n;
	while (length)
	{
		ft_putchar_fd((tmp / length) + '0', fd);
		tmp %= length;
		length /= 10;
	}
}
