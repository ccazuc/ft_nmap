/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strsplit.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ccazuc <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/07 07:39:44 by ccazuc            #+#    #+#             */
/*   Updated: 2018/06/18 10:18:53 by ccazuc           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static int		get_nb_word(const char *str, char match)
{
	int		i;
	int		nb_word;
	int		last_word;
	char	tmp;

	i = -1;
	tmp = str[0];
	last_word = (tmp == match) ? 0 : 1;
	nb_word = 0;
	while (str[++i])
	{
		tmp = str[i];
		if (tmp == match && !last_word)
			continue ;
		if (tmp == match && last_word)
		{
			nb_word++;
			last_word = 0;
		}
		else
			last_word = 1;
	}
	if (i == 1)
		return (-1);
	return ((tmp == match) ? nb_word : nb_word + 1);
}

static void		get_n_word(const char *str, char **result, int v[2], int *index)
{
	int		i;
	int		res_i;

	i = *index;
	while (str[++i])
		if (str[i] == v[STR_SPLIT_MATCH])
			break ;
	result[v[STR_SPLIT_CUR_WRD]] = malloc((i - *index + 1));
	i = *index - 1;
	res_i = 0;
	while (str[++i])
	{
		if (str[i] == v[STR_SPLIT_MATCH])
			break ;
		result[v[STR_SPLIT_CUR_WRD]][res_i] = str[i];
		++res_i;
	}
	result[v[STR_SPLIT_CUR_WRD]][res_i] = 0;
	*index = i;
}

char			**ft_strsplit(const char *s, char c)
{
	int		i;
	int		tot_word;
	char	**result;
	int		value[2];

	if (!s)
		return (NULL);
	i = -1;
	value[STR_SPLIT_MATCH] = c;
	tot_word = get_nb_word(s, c);
	if (tot_word == -1)
		return (NULL);
	if (!(result = malloc((tot_word + 1) * sizeof(*result))))
		return (NULL);
	value[STR_SPLIT_CUR_WRD] = 0;
	while (s[++i] && value[STR_SPLIT_CUR_WRD] < tot_word)
		if (s[i] != c)
		{
			get_n_word(s, result, value, &i);
			value[STR_SPLIT_CUR_WRD]++;
		}
	result[value[STR_SPLIT_CUR_WRD]] = 0;
	return (result);
}
