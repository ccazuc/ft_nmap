#include "ft_nmap.h"

static void send_tcp_packet(t_tcp_packet *packet, t_worker *worker)
{
	int sent;

	if ((sent = sendto(worker->tcp_socket, packet, sizeof(*packet) + worker->env->params.payload_size, 0, worker->env->dst_sockaddr, worker->env->dst_sockaddrlen)) == -1)
		ft_exit("sendto failed, exiting", EXIT_FAILURE);
	printf("sent %d to port %d\n", sent, ntohs(packet->tcp_hdr.dest));
}

static void send_syn_scan(t_worker *worker, t_port_result *port_result, t_scan_datas *scan_datas)
{
	t_tcp_packet packet;

	build_tcp_packet(&packet, worker, port_result, scan_datas);
	packet.tcp_hdr.syn = 1;
	packet.tcp_hdr.seq = htons(SYN_SEQ);
	packet.tcp_hdr.check = build_tcp_checksum(&packet, worker, port_result, scan_datas);
	send_tcp_packet(&packet, worker);
	scan_datas->last_scan = get_time();
	scan_datas->sent = 1;
}

static void send_null_scan(t_worker *worker, t_port_result *port_result, t_scan_datas *scan_datas)
{
	t_tcp_packet packet;

	build_tcp_packet(&packet, worker, port_result, scan_datas);
	packet.tcp_hdr.seq = htons(NULL_SEQ);
	packet.tcp_hdr.check = build_tcp_checksum(&packet, worker, port_result, scan_datas);
	send_tcp_packet(&packet, worker);
	scan_datas->last_scan = get_time();
	scan_datas->sent = 1;
}

static void send_ack_scan(t_worker *worker, t_port_result *port_result, t_scan_datas *scan_datas)
{
	(void)worker;
	(void)port_result;
	(void)scan_datas;
}

static void send_fin_scan(t_worker *worker, t_port_result *port_result, t_scan_datas *scan_datas)
{
	t_tcp_packet packet;

	build_tcp_packet(&packet, worker, port_result, scan_datas);
	packet.tcp_hdr.fin = 1;
	packet.tcp_hdr.seq = htons(FIN_SEQ);
	packet.tcp_hdr.check = build_tcp_checksum(&packet, worker, port_result, scan_datas);
	send_tcp_packet(&packet, worker);
	scan_datas->last_scan = get_time();
	scan_datas->sent = 1;
}

static void send_xmas_scan(t_worker *worker, t_port_result *port_result, t_scan_datas *scan_datas)
{
	t_tcp_packet packet;

	build_tcp_packet(&packet, worker, port_result, scan_datas);
	packet.tcp_hdr.fin = 1;
	packet.tcp_hdr.psh = 1;
	packet.tcp_hdr.urg = 1;
	packet.tcp_hdr.seq = htons(XMAS_SEQ);
	packet.tcp_hdr.check = build_tcp_checksum(&packet, worker, port_result, scan_datas);
	send_tcp_packet(&packet, worker);
	scan_datas->last_scan = get_time();
	scan_datas->sent = 1;
}

static void send_udp_scan(t_worker *worker, t_port_result *port_result, t_scan_datas *scan_datas)
{
	(void)worker;
	(void)port_result;
	(void)scan_datas;
}

void send_scan(t_worker *worker, t_port_result *port_result, t_scan_datas *scan_datas)
{
	if (scan_datas->type == SCAN_SYN)
	{
		send_syn_scan(worker, port_result, scan_datas);
	}
	else if (scan_datas->type == SCAN_NULL)
	{
		send_null_scan(worker, port_result, scan_datas);
	}
	else if (scan_datas->type == SCAN_ACK)
	{
		send_ack_scan(worker, port_result, scan_datas);
	}
	else if (scan_datas->type == SCAN_FIN)
	{
		send_fin_scan(worker, port_result, scan_datas);
	}
	else if (scan_datas->type == SCAN_XMAS)
	{
		send_xmas_scan(worker, port_result, scan_datas);
	}
	else if (scan_datas->type == SCAN_UDP)
	{
		send_udp_scan(worker, port_result, scan_datas);
	}
}
