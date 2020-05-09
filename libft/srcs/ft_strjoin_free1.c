/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strjoin_free12.c                                :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ccazuc <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/08 09:14:47 by ccazuc            #+#    #+#             */
/*   Updated: 2017/11/14 13:48:39 by ccazuc           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdio.h>

char	*ft_strjoin_free1(char *s1, char *s2)
{
	char	*result;
	int		i;
	int		j;
	int		size;

	i = 0;
	while (s1 && s1[i])
		++i;
	size = i;
	i = 0;
	while (s2 && s2[i])
		++i;
	size = size + i + 1;
	if (!(result = malloc(size * sizeof(*result))))
		return (NULL);
	i = -1;
	while (s1 && s1[++i])
		result[i] = s1[i];
	i = i == -1 ? i + 1 : i;
	j = -1;
	while (s2 && s2[++j])
		result[i + j] = s2[j];
	result[i + j] = '\0';
	free(s1);
	return (result);
}
