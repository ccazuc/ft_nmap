#include "ft_nmap.h"



static void parse_str_arg(t_env *env, char *arg, int32_t *index)
{
	if (!ft_strcmp(arg, "help"))
	{
		print_usage(EXIT_SUCCESS);
	}
	else
	{
		printf("Bad option `--%s' (argc %d)\n", arg, *index);
		exit(EXIT_FAILURE);
	}
}

static void parse_arg(t_env *env, int argc, char **argv, int32_t *index)
{
	char *arg = argv[*index];
	if (!arg[0])
		return;
	if (arg[0] == '-')
	{
		if (arg[1] == '-')
		{
			parse_str_arg(env, arg + 2, index);
			return;
		}
		uint32_t i = 0;
		while (arg[++i])
		{
			if (arg[i] == 'h')
				print_usage(EXIT_SUCCESS);
			else
				print_invalid_param(arg[i], *index);
		}
	}
	else if (!env->dst_param)
		env->dst_param = arg;
	else
	{
		printf("Extra arg `%s' (position 3, argc %d)\n", arg, *index);
		exit(EXIT_FAILURE);
	}
}

void parse_args(t_env *env, int argc, char **argv)
{
	int32_t i = 0;
	while (++i < argc)
		parse_arg(env, argc, argv, &i);
}
