#include "ft_nmap.h"

void print_usage(int32_t code)
{
	printf("Usage:\n  nmap [ -sS ] [ -sX ] [ -sA ] [ -sU ] [ -sN ] [ -sF ] [ -p 1-100 ] [ -r ] [ - w ] [ -t ] host\n");
	printf("Options:\n");
	printf("  -sS:						use SYN scan\n");
	printf("  -sX:						use XMAS scan\n");
	printf("  -sA:						use ACK scan\n");
	printf("  -sU:						use UDP scan\n");
	printf("  -sN:						use NULL scan\n");
	printf("  -sF:						use FIN scan\n");
	printf("  -p <port ranges> --port=<port ranges>\n");
	printf("    <port ranges> format: 5; 5-100\n");
	printf("  -r --retry=					number of retry for each scan\n");
	printf("  -w --wait=					time to wait before sending another retry in ms\n");
	printf("  -t --threads=					number of thread to use\n");
	printf("If no scans are specified, nmap uses all scans\n");
	printf("Default ports are 1-1024\n");
	printf("Examples:\n");
	printf("  ./ft_nmap -sSU -p 53-80 -r 3 -w 150 -t 3 scanme.nmap.org\n");
	exit(code);
}

void print_invalid_param(uint8_t param, uint32_t index)
{
	printf("Bad option \'-%c\' (argc %d)\n", param, index);
	exit(EXIT_FAILURE);
}

void print_unknown_dst(char *dst)
{
	printf("ping: %s: Nom ou service inconnu\n", dst);
	exit(EXIT_FAILURE);
}

char *get_scan_name(uint8_t scan)
{
	if (scan == SCAN_SYN)
		return "SYN";
	if (scan == SCAN_NULL)
		return "NULL";
	if (scan == SCAN_ACK)
		return "ACK";
	if (scan == SCAN_FIN)
		return "FIN";
	if (scan == SCAN_XMAS)
		return "XMAS";
	if (scan == SCAN_UDP)
		return "UDP";
	return NULL;
}

char *get_result_name(uint8_t state)
{
	if (state == STATE_CLOSED)
		return "Closed";
	if (state == STATE_OPENED)
		return "Opened";
	if (state == STATE_FILTERED)
		return "Filtered";
	if (state == STATE_UNFILTERED)
		return "Unfiltered";
	if (state == STATE_OPEN_FILTERED)
		return "Open|Filtered";
	return NULL;
}

void print_configuration(t_env *env)
{
	printf("Scan Configuration\n");
	printf("Target IP %s (%s)\n", env->dst_param, env->dst_name);
	printf("Number of ports to scan: %d\n", env->params.max_port - env->params.min_port + 1);
	printf("Scans to be performed:");
	for (uint8_t i = 0; i < env->number_diff_scans; ++i)
	{
		printf(" %s", get_scan_name(env->scan_list[i]));
	}
	printf("\nNumber of threads: %d\n", env->params.num_threads);
	printf("Scanning..\n........\n");
}

static uint8_t is_port_opened(t_env *env, t_port_result *port_result)
{
	for (uint8_t i = 0; i < env->number_diff_scans; ++i)
	{
		if (port_result->scans[i].type == SCAN_SYN && port_result->scans[i].state == STATE_OPENED)
			return 1;
		if (port_result->scans[i].type == SCAN_UDP && port_result->scans[i].state == STATE_OPENED)
			return 1;
	}
	return 0;
}

static char *get_service_name(uint16_t port)
{
	struct servent *res;

	if (!(res = getservbyport(htons(port), NULL)))
		return "unknown";
	return res->s_name ? res->s_name : "unknown";
}

static void print_port_last_line(t_env *env, t_port_result *port_result)
{
	char *tmp;
	if (env->number_diff_scans == 1)
	{
		printf("%-10sservice\n", "");
	}
	else
	{
		if (!(tmp = malloc(strlen(get_scan_name(port_result->scans[env->number_diff_scans - 1].type)) + strlen(get_result_name(port_result->scans[env->number_diff_scans - 1].state)) + 3)))
			ft_exit("Error, could not malloc tmp str", EXIT_FAILURE);
		memset(tmp, 0, strlen(get_scan_name(port_result->scans[env->number_diff_scans - 1].type)) + strlen(get_result_name(port_result->scans[env->number_diff_scans - 1].state) + 3));
		strcat(tmp, get_scan_name(port_result->scans[env->number_diff_scans - 1].type));
		strcat(tmp, "(");
		strcat(tmp, get_result_name(port_result->scans[env->number_diff_scans - 1].state));
		strcat(tmp, ")");
		printf(" %-45s %-20s %-1s\n", "", tmp, "mdr");
	}
}

static void print_port(t_env *env, t_port_result *port_result)
{
	printf("%-10d %-35s ", port_result->port, get_service_name(port_result->port));
	printf("%s(%s)", get_scan_name(port_result->scans[0].type), get_result_name(port_result->scans[0].state));
	if (env->number_diff_scans != 1)
		printf("\n");
	for (uint8_t i = 1; i < env->number_diff_scans - 1; ++i)
		printf(" %-45s %s(%s)\n", "", get_scan_name(port_result->scans[i].type), get_result_name(port_result->scans[i].state));
	print_port_last_line(env, port_result);
	printf("\n");
}

void print_result(t_env *env)
{
	printf("Scan Took %.3f secs\n", (get_time() - env->start_time) / 1000000.f);
	printf("Open ports:\n");
	printf("%-10s %-35s %-20s %-10s\n", "Port", "Service Name (if applicable)", "Results", "Conclusion");
	printf("------------------------------------------------------------------------------\n");
	for (uint16_t i = 0; i < env->params.num_threads; ++i)
	{
		for (uint16_t j = 0; j < env->ports_per_thread && env->threads[i].ports_result[j].port <= env->params.max_port; ++j)
		{
			if (is_port_opened(env, &env->threads[i].ports_result[j]))
				print_port(env, &env->threads[i].ports_result[j]);
		}
	}
	printf("\nClosed/Filtered/Unfiltered/Open|Filtered ports:\n");
	printf("%-10s %-35s %-20s %-10s\n", "Port", "Service Name (if applicable)", "Results", "Conclusion");
	printf("------------------------------------------------------------------------------\n");
	for (uint16_t i = 0; i < env->params.num_threads; ++i)
	{
		for (uint16_t j = 0; j < env->ports_per_thread && env->threads[i].ports_result[j].port <= env->params.max_port; ++j)
		{
			if (!is_port_opened(env, &env->threads[i].ports_result[j]))
				print_port(env, &env->threads[i].ports_result[j]);
		}
	}
}
