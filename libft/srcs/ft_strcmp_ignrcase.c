/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strcmp.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ccazuc <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/07 06:11:54 by ccazuc            #+#    #+#             */
/*   Updated: 2017/11/07 18:45:04 by ccazuc           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

int	match(char c1, char c2)
{
	if (c1 >= 'a' && c1 <= 'z')
		return (c1 == c2 || c1 - 32 == c2 ? 1 : 0);
	if (c1 >= 'A' && c1 <= 'Z')
		return (c1 == c2 || c1 + 32 == c2 ? 1 : 0);
	return (c1 == c2 ? 1 : 0);
}

int	ft_strcmp_ignrcase(const char *s1, const char *s2)
{
	int i;

	i = -1;
	while (s1[++i] && s2[i])
		if (!match(s1[i], s2[i]))
			return ((unsigned char)s1[i] - (unsigned char)s2[i]);
	if (s2[i])
		return (-(unsigned char)s2[i]);
	if (s1[i])
		return ((unsigned char)s1[i]);
	return (0);
}
