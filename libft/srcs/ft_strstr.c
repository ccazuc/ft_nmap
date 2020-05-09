/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strstr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ccazuc <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/07 06:07:03 by ccazuc            #+#    #+#             */
/*   Updated: 2017/11/07 06:10:47 by ccazuc           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strstr(const char *meule_de_foin, const char *aiguille)
{
	int		i;
	int		j;
	int		to_find_len;

	i = ft_strlen(aiguille);
	if (i == 0)
		return (char*)(meule_de_foin);
	to_find_len = i;
	i = -1;
	while (meule_de_foin[++i])
	{
		j = 0;
		while (meule_de_foin[i + j] == aiguille[j])
		{
			if (j == to_find_len - 1)
				return ((char*)(meule_de_foin + i));
			j++;
		}
	}
	return (NULL);
}
