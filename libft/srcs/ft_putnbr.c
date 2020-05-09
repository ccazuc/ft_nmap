/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_putnbr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ccazuc <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/07 07:25:09 by ccazuc            #+#    #+#             */
/*   Updated: 2017/11/07 16:57:49 by ccazuc           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static void		print_min_value(void)
{
	ft_putchar('-');
	ft_putchar('2');
	ft_putchar('1');
	ft_putchar('4');
	ft_putchar('7');
	ft_putchar('4');
	ft_putchar('8');
	ft_putchar('3');
	ft_putchar('6');
	ft_putchar('4');
	ft_putchar('8');
}

void			ft_putnbr(int n)
{
	int		tmp;
	int		length;

	if (n == -2147483648)
	{
		print_min_value();
		return ;
	}
	length = 1;
	if (n < 0)
	{
		ft_putchar('-');
		n = -n;
	}
	tmp = n;
	while ((tmp = (tmp / 10)) > 0)
		length *= 10;
	tmp = n;
	while (length)
	{
		ft_putchar((tmp / length) + '0');
		tmp %= length;
		length /= 10;
	}
}
