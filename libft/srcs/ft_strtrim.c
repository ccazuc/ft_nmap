/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strtrim.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ccazuc <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/07 06:38:49 by ccazuc            #+#    #+#             */
/*   Updated: 2017/11/15 08:22:03 by ccazuc           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strtrim(char const *s)
{
	int		i;
	int		start;
	int		end;

	if (!s)
		return (NULL);
	i = 0;
	while (s[i] && (s[i] == ' ' || s[i] == '\n' || s[i] == '\t'))
		++i;
	start = i;
	i = ft_strlen(s) - 1;
	end = 0;
	while (i > 0 && (s[i] == ' ' || s[i] == '\n' || s[i] == '\t'))
		--i;
	end = i + 1;
	if (end < start || end == start)
		return (ft_memalloc(0));
	return (ft_strsub(s, start, end - start));
}
