/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstmap.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ccazuc <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/07 09:29:10 by ccazuc            #+#    #+#             */
/*   Updated: 2017/11/07 17:27:01 by ccazuc           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

t_list	*ft_lstmap(t_list *lst, t_list *(*f)(t_list *elem))
{
	t_list	*result;
	t_list	*result_elem;

	if (lst)
	{
		result = (*f)(lst);
		result_elem = result;
		lst = lst->next;
		while (lst)
		{
			result_elem->next = (*f)(lst);
			result_elem = result_elem->next;
			lst = lst->next;
		}
		result_elem->next = NULL;
		return (result);
	}
	return (NULL);
}
