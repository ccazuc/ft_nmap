#include "ft_nmap.h"

static t_env *create_env(void)
{
	t_env *env;

	if (!(env = malloc(sizeof(*env))))
		ft_exit("Error, could not malloc env", EXIT_FAILURE);
	env->params.count = 3;
	env->params.payload_size = 0;
	env->params.verbose = 0;
	env->params.protocol = IPPROTO_ICMP;
	env->params.af = AF_INET;
	env->params.parsed_payload_size = 0;
	env->params.min_port = 1;
	env->params.max_port = 1024;
	env->params.num_threads = 1;
	env->params.scan_timeout = 300;
	env->params.scan_max_retry = 5;
	env->params.host_port = 54351;
	env->params.parsed_scan = 0;
	env->dst_param = NULL;
	env->dst_bin = NULL;
	env->dst_name = NULL;
	env->dst_subname = NULL;
	env->dst_sockaddr = NULL;
	env->dst_sockaddrlen = 0;
	env->running = 1;
	env->number_diff_scans = 6;
	ft_memset(env->scan_list, 0, sizeof(env->scan_list));
	env->scan_list[0] = SCAN_SYN;
	env->scan_list[1] = SCAN_NULL;
	env->scan_list[2] = SCAN_ACK;
	env->scan_list[3] = SCAN_FIN;
	env->scan_list[4] = SCAN_XMAS;
	env->scan_list[5] = SCAN_UDP;
	return env;
}

int main(int argc, char **argv)
{
	t_env *env;
	if (argc == 1)
		print_usage(EXIT_FAILURE);
	if (getuid())
		ft_exit("Error, nmap requires root privileges.", EXIT_FAILURE);
	env = create_env();
	parse_args(env, argc, argv);
	if (!env->dst_param)
		print_usage(EXIT_FAILURE);
	resolve_host(env);
	get_local_ip(env);
	print_configuration(env);
	env->start_time = get_time();
	create_threads(env);
	while (env->running)
	{
		env->running = 0;
		for (uint8_t i = 0; i < env->params.num_threads; ++i)
		{
			if (env->threads[i].running)
			{
				env->running = 1;
				usleep(10000);
				break;
			}
		}
	}
	print_result(env);
}
