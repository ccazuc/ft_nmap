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
	env->params.min_port = 79;
	env->params.max_port = 79;
	env->params.num_threads = 1;
	env->params.scan_timeout = 1000;
	env->params.scan_max_retry = 5;
	env->params.host_port = 54351;
	env->dst_param = NULL;
	env->dst_bin = NULL;
	env->dst_name = NULL;
	env->dst_subname = NULL;
	env->dst_sockaddr = NULL;
	env->dst_sockaddrlen = 0;
	env->count = 0;
	env->running = 1;
	env->max_hops = 30;
	env->send_per_loop = 3;
	env->sent_hops = 0;
	env->number_diff_scans = 4;
	env->scan_list[0] = SCAN_NULL;
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
	//if (getuid())
	//	ft_exit("tmp", EXIT_FAILURE);
	env = create_env();
	parse_args(env, argc, argv);
	resolve_host(env);
	get_local_ip(env);
	create_threads(env);
	/*parse_args(env, argc, argv);
	if (!env->dst_param)
		print_usage(EXIT_FAILURE);
	resolve_host(env);
	create_threads(env);*/
	while (env->running)
	{
		env->running = 0;
		for (uint8_t i = 0; i < env->params.num_threads; ++i)
		{
			if (env->threads[i].running)
			{
				env->running = 1;
				sleep(1);
				break;
			}
		}
	}
	while (1);
}
