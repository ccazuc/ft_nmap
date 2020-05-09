/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strnstr.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ccazuc <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/07 06:10:51 by ccazuc            #+#    #+#             */
/*   Updated: 2017/11/08 07:24:04 by ccazuc           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strnstr(const char *big, const char *little, size_t len)
{
	size_t	i;
	int		j;
	int		to_find_len;

	i = ft_strlen(little);
	if (i == 0)
		return (char*)(big);
	to_find_len = i;
	i = 0;
	while (big[i] && i < len)
	{
		j = 0;
		while (big[i + j] == (unsigned char)little[j] && i + j < len)
		{
			if (j == to_find_len - 1)
				return ((char*)(big + i));
			j++;
		}
		++i;
	}
	return (NULL);
}
