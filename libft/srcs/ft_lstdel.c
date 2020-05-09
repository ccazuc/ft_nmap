/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstdel.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ccazuc <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/07 09:15:06 by ccazuc            #+#    #+#             */
/*   Updated: 2017/11/07 09:22:48 by ccazuc           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	ft_lstdel(t_list **alst, void (*del)(void*, size_t))
{
	t_list	*next;
	t_list	*list;

	list = *alst;
	while (list)
	{
		(*del)(list->content, list->content_size);
		next = list->next;
		free(list);
		list = next;
	}
	*alst = NULL;
}
