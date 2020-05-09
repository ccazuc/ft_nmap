#include "ft_nmap.h"

void create_sockets(t_worker *worker)
{
	int osef;

	if ((worker->icmp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1)
		ft_exit("Error, could not create ICMP socket", EXIT_FAILURE);
	osef = 1;
	if (setsockopt(worker->icmp_socket, IPPROTO_IP, IP_HDRINCL, &osef, sizeof(osef)) == -1)
		ft_exit("Error, could not setsockopt for ICMP socket", EXIT_FAILURE);
	if ((worker->udp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == -1)
		ft_exit("Error, could not create UDP socket", EXIT_FAILURE);
	osef = 1;
	if (setsockopt(worker->udp_socket, IPPROTO_IP, IP_HDRINCL, &osef, sizeof(osef)) == -1)
		ft_exit("Error, could not setsockopt for UDP socket", EXIT_FAILURE);
	if ((worker->tcp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
		ft_exit("Error, could not create TCP socket", EXIT_FAILURE);
	osef = 1;
	if (setsockopt(worker->tcp_socket, IPPROTO_IP, IP_HDRINCL, &osef, sizeof(osef)) == -1)
		ft_exit("Error, could not setsockopt for TCP socket", EXIT_FAILURE);
}
