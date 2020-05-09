#include "ft_nmap.h"

void print_usage(int32_t code)
{
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

void print_version()
{
	ft_exit("Modern traceroute for Linux, version i.d.k\nCopyright (c) 2020 Mideas", EXIT_SUCCESS);
}
