/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strsub.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ccazuc <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/07 06:36:27 by ccazuc            #+#    #+#             */
/*   Updated: 2017/11/15 08:26:22 by ccazuc           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strsub(char const *s, unsigned int start, size_t len)
{
	char	*result;
	size_t	i;

	if (!s)
		return (NULL);
	if (!(result = malloc(len + 1)))
		return (NULL);
	i = 0;
	while (i < len)
	{
		result[i] = s[start + i];
		++i;
	}
	result[i] = '\0';
	return (result);
}
