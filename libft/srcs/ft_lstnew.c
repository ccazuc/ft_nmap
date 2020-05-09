/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstnew.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ccazuc <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/07 09:02:04 by ccazuc            #+#    #+#             */
/*   Updated: 2017/11/08 07:18:18 by ccazuc           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdio.h>

t_list	*ft_lstnew(void const *content, size_t content_size)
{
	t_list		*result;

	if (!(result = malloc(sizeof(*result))))
		return (NULL);
	if (content && content_size > 0)
	{
		if (!(result->content = malloc(content_size)))
			return (NULL);
		ft_memcpy(result->content, content, content_size);
		result->content_size = content_size;
	}
	else
	{
		result->content = NULL;
		result->content_size = 0;
	}
	result->next = NULL;
	return (result);
}
