#include "ft_nmap.h"

void resolve_host(t_env *env)
{
	struct addrinfo hints;
	struct addrinfo *result;
	char ip[16];

	ft_memset(&hints, 0, sizeof(hints));
	hints.ai_family = env->params.af;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_protocol = env->params.protocol;
	if (getaddrinfo(env->dst_param, NULL, &hints, &result) || !result)
		print_unknown_dst(env->dst_param);
	ft_memset(ip, 0, sizeof(ip));
	if (!(env->dst_bin = malloc(sizeof(*env->dst_bin))))
		ft_exit("Error, could not malloc dst_bin", EXIT_FAILURE);
	memcpy(env->dst_bin, &((struct sockaddr_in*)result->ai_addr)->sin_addr, sizeof(*env->dst_bin));
	if (!inet_ntop(env->params.af, &((struct sockaddr_in*)result->ai_addr)->sin_addr, ip, INET_ADDRSTRLEN))
		print_unknown_dst(env->dst_param);
	if (!(env->dst_name = malloc(strlen(ip) + 1)))
		ft_exit("Error, could not malloc dst_name", EXIT_FAILURE);
	strcpy(env->dst_name, ip);
	if (!(env->dst_sockaddr = malloc(sizeof(*env->dst_sockaddr))))
		ft_exit("Error, could not malloc dst_sockaddr", EXIT_FAILURE);
	memset(env->dst_sockaddr, 0, sizeof(*env->dst_sockaddr));
	memcpy(env->dst_sockaddr, result->ai_addr, result->ai_addrlen);
	env->dst_sockaddrlen = result->ai_addrlen;
	free(result);
	struct in_addr addr;
	if (!inet_aton(env->dst_name, &addr))
		return;
	struct hostent *hent;
	if (!(hent = gethostbyaddr((char*)&(addr.s_addr), sizeof(addr.s_addr), env->params.af)))
		return;
	if (!(env->dst_subname = malloc(strlen(hent->h_name) + 1)))
		ft_exit("Error, could not malloc dst_subname", EXIT_FAILURE);
	strcpy(env->dst_subname, hent->h_name);
}

void get_local_ip(t_env *env)
{
	struct ifaddrs *list = NULL;

	if (getifaddrs(&list))
		ft_exit("Error, getifaddrs failed", EXIT_FAILURE);
	for (struct ifaddrs *tmp = list; tmp; tmp = tmp->ifa_next)
	{
		if (!tmp->ifa_addr || tmp->ifa_addr->sa_family != AF_INET)
			continue;
		if (!ft_strcmp(tmp->ifa_name, "lo"))
		{
			if ((env->dst_bin->s_addr & 0xFF) != 0x7F)
				continue;
			env->src_s_addr = ((struct sockaddr_in*)tmp->ifa_addr)->sin_addr.s_addr;
			free(list);
			return;
		}
		else
		{
			env->src_s_addr = ((struct sockaddr_in*)tmp->ifa_addr)->sin_addr.s_addr;
			free(list);
			return;
		}
	}
	free(list);
}
