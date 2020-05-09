/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strsub_start.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ccazuc <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/08 09:34:51 by ccazuc            #+#    #+#             */
/*   Updated: 2017/11/08 10:26:32 by ccazuc           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strsub_start(char *s, int start)
{
	char	*result;
	size_t	i;

	if (!(result = malloc(ft_strlen(s) - start + 1)))
		return (NULL);
	i = 0;
	while (s[start + i])
	{
		result[i] = s[start + i];
		++i;
	}
	result[i] = '\0';
	return (result);
}
