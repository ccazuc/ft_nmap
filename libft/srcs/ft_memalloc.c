/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memalloc.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ccazuc <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/07 06:19:34 by ccazuc            #+#    #+#             */
/*   Updated: 2017/11/07 06:25:45 by ccazuc           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memalloc(size_t size)
{
	void	*result;
	int		i;

	if (!(result = malloc(size)))
		return (NULL);
	i = -1;
	while (++i < (int)size)
		((unsigned char*)result)[i] = 0;
	return (result);
}
