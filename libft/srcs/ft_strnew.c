/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strnew.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ccazuc <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/07 06:27:33 by ccazuc            #+#    #+#             */
/*   Updated: 2017/11/07 18:56:21 by ccazuc           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strnew(size_t size)
{
	char	*result;
	size_t	i;

	if (!(result = malloc(size + 1)))
		return (NULL);
	i = 0;
	while (i < size)
	{
		result[i] = '\0';
		++i;
	}
	result[i] = '\0';
	return (result);
}
