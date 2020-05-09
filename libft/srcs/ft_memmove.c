/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memmove.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ccazuc <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/07 05:51:21 by ccazuc            #+#    #+#             */
/*   Updated: 2017/11/15 07:24:43 by ccazuc           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memmove(void *dest, const void *src, size_t n)
{
	size_t	i;

	i = -1;
	if (n > 0 && dest < src)
		while (++i < n)
			((unsigned char*)dest)[i] = ((unsigned char*)src)[i];
	else if (n > 0)
	{
		i = n + 3;
		while (--i > 0)
			((unsigned char*)dest)[i - 1] = ((unsigned char*)src)[i - 1];
		((unsigned char*)dest)[n] = '\0';
	}
	return (dest);
}
