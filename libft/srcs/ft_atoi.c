/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_atoi.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ccazuc <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/07 08:21:19 by ccazuc            #+#    #+#             */
/*   Updated: 2017/11/08 07:21:17 by ccazuc           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static int		ft_get_ini_pos(const char *str)
{
	int		i;
	char	tmp;
	int		length;

	i = 0;
	while (str[i])
		i++;
	length = i;
	i = -1;
	while (str[++i])
	{
		tmp = str[i];
		if (tmp >= '0' && tmp <= '9')
			return (i);
		if ((tmp == '-' || tmp == '+') && i < length - 1
				&& str[i + 1] >= '0' && str[i + 1] <= '9')
			return (i);
		if (tmp != ' ' && tmp != '\v' && tmp != '\t'
				&& tmp != '\f' && tmp != '\n' && tmp != '\r')
			return (-1);
	}
	return (-1);
}

static int		get_end_pos(int i, const char *str)
{
	char	tmp;

	while (str[++i])
	{
		tmp = str[i];
		if (tmp < '0' || tmp > '9')
			return (i--);
	}
	return (i);
}

int				ft_atoi(const char *str)
{
	int		i;
	int		result;
	int		tmp_num;
	char	is_neg;
	char	length;

	result = 0;
	i = ft_get_ini_pos(str);
	if (i == -1)
		return (0);
	length = get_end_pos(i, str);
	if (length == i)
		return (0);
	is_neg = str[i] == '-';
	while (str[i] && i < length)
	{
		tmp_num = result;
		if (str[i] >= '0' && str[i] <= '9')
			result = result * 10 + (str[i] - '0');
		if (tmp_num != ((result - str[i] + '0') / 10))
			return (-1);
		i++;
	}
	return (is_neg == 0 ? result : -result);
}
