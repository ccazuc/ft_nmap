#include "ft_nmap.h"

static void parse_scan(t_env *env, uint8_t scan_type)
{
	if (env->params.parsed_scan)
	{
		for (uint8_t i = 0; i < env->number_diff_scans; ++i)
		{
			if (env->scan_list[i] == scan_type)
				return;
		}
		env->scan_list[env->number_diff_scans] = scan_type;
		++env->number_diff_scans;
	}
	else
	{
		env->number_diff_scans = 1;
		env->scan_list[env->number_diff_scans - 1] = scan_type;
		env->params.parsed_scan = 1;
	}
}

static void parse_ports(t_env *env, char *arg)
{
	int min_port = ft_atoi(arg);
	int max_port = -1;

	if (!arg[0])
		ft_exit("Error, invalid port format", EXIT_FAILURE);
	if (min_port < 0)
		ft_exit("Error, invalid port format", EXIT_FAILURE);
	for (uint8_t i = 0; arg[i]; ++i)
	{
		if (arg[i] == '-')
		{
			if (!arg[i + 1])
				ft_exit("Error, invalid port format", EXIT_FAILURE);
			max_port = ft_atoi(arg + i + 1);
		}
	}
	env->params.min_port = min_port;
	if (max_port == -1)
		env->params.max_port = env->params.min_port;
	else
		env->params.max_port = max_port;
}

static void parse_threads(t_env *env, char *arg)
{
	int threads = ft_atoi(arg);

	if (threads <= 0 || threads > 128)
		ft_exit("Error, invalid thread value", EXIT_FAILURE);
	env->params.num_threads = threads;
}

static void parse_wait(t_env *env, char *arg)
{
	int wait = ft_atoi(arg);

	if (wait <= 0)
		ft_exit("Error, invalid wait value", EXIT_FAILURE);
	env->params.scan_timeout = wait;
}

static void parse_retries(t_env *env, char *arg)
{
	int retries = ft_atoi(arg);

	if (retries <= 0)
		ft_exit("Error, invalid retry value", EXIT_FAILURE);
	env->params.scan_max_retry = retries;
}

static void parse_str_arg(t_env *env, char *arg, int32_t *index)
{
	if (!ft_strcmp(arg, "help"))
	{
		print_usage(EXIT_SUCCESS);
	}
	else if (!ft_strncmp(arg, "threads=", 8))
	{
		parse_threads(env, arg + 8);
	}
	else if (!ft_strncmp(arg, "retry=", 6))
	{
		parse_retries(env, arg + 6);
	}
	else if (!ft_strncmp(arg, "wait=", 5))
	{
		parse_wait(env, arg + 5);
	}
	else if (!ft_strncmp(arg, "port=", 5))
	{
		parse_ports(env, arg + 5);
	}
	else
	{
		printf("Bad option `--%s' (argc %d)\n", arg, *index);
		exit(EXIT_FAILURE);
	}
}

static void check_argc(int32_t index, uint8_t num_args, char *param, int argc)
{
	if (index + num_args >= argc)
	{
		printf("Error, arg %s required %d arguments\n", param, num_args);
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
			{
				print_usage(EXIT_SUCCESS);
			}
			else if (arg[i] == 's')
			{
				if (!arg[++i])
					print_usage(EXIT_FAILURE);
				while (arg[i])
				{
					if (arg[i] == 'S')
						parse_scan(env, SCAN_SYN);
					else if (arg[i] == 'A')
						parse_scan(env, SCAN_ACK);
					else if (arg[i] == 'N')
						parse_scan(env, SCAN_NULL);
					else if (arg[i] == 'F')
						parse_scan(env, SCAN_FIN);
					else if (arg[i] == 'X')
						parse_scan(env, SCAN_XMAS);
					else if (arg[i] == 'U')
						parse_scan(env, SCAN_UDP);
					else
						print_usage(EXIT_FAILURE);
					++i;
				}
				break;
			}
			else if (arg[i] == 'p')
			{
				check_argc(*index, 1, "-p", argc);
				parse_ports(env, argv[++*index]);
			}
			else if (arg[i] == 't')
			{
				check_argc(*index, 1, "-t", argc);
				parse_threads(env, argv[++*index]);
				break;
			}
			else if (arg[i] == 'w')
			{
				check_argc(*index, 1, "-w", argc);
				parse_wait(env, argv[++*index]);
				break;
			}
			else if (arg[i] == 'r')
			{
				check_argc(*index, 1, "-r", argc);
				parse_retries(env, argv[++*index]);
				break;
			}
			else
			{
				print_invalid_param(arg[i], *index);
			}
		}
	}
	else if (!env->dst_param)
		env->dst_param = arg;
	else
	{
		ft_exit("Error, extra param", EXIT_FAILURE);
	}
}

void parse_args(t_env *env, int argc, char **argv)
{
	int32_t i = 0;
	while (++i < argc)
		parse_arg(env, argc, argv, &i);
}
