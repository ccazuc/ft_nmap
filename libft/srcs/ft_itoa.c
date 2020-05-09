/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_itoa.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ccazuc <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/07 10:09:45 by ccazuc            #+#    #+#             */
/*   Updated: 2017/11/08 07:20:46 by ccazuc           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static int	get_len(int n)
{
	int		size;

	size = n > 0 ? 1 : 2;
	n = n > 0 ? n : -n;
	while (n > 0)
	{
		n /= 10;
		++size;
	}
	return (size);
}

static char	*do_malloc(int *n)
{
	char	*result;

	if (!(result = malloc(get_len(*n))))
		return (NULL);
	result[0] = '\0';
	if (*n < 0)
	{
		*n = -*n;
		result[0] = '-';
	}
	return (result);
}

static char	*handle_default_value(int n)
{
	if (n == -2147483648)
		return (ft_strdup("-2147483648"));
	if (n == 2147483647)
		return (ft_strdup("2147483647"));
	return (ft_strdup("0"));
}

char		*ft_itoa(int n)
{
	int		tmp;
	int		length;
	char	*result;
	int		i;

	if (n == -2147483648 || n == 0 || n == 2147483647)
		return (handle_default_value(n));
	if (!(result = do_malloc(&n)))
		return (NULL);
	length = 1;
	tmp = n;
	while ((tmp = (tmp / 10)) > 0)
		length *= 10;
	tmp = n;
	i = result[0] == '-' ? 1 : 0;
	while (length)
	{
		result[i] = ((tmp / length) + '0');
		tmp %= length;
		length /= 10;
		++i;
	}
	result[i] = '\0';
	return (result);
}
