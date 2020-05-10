#include "ft_nmap.h"

static void send_tcp_packet(t_tcp_packet *packet, t_worker *worker)
{
	int sent;

	if ((sent = sendto(worker->tcp_socket, packet, sizeof(*packet) + worker->env->params.payload_size, 0, worker->env->dst_sockaddr, worker->env->dst_sockaddrlen)) == -1)
		ft_exit("sendto failed, exiting", EXIT_FAILURE);
	printf("sent %d to port %d\n", sent, ntohs(packet->tcp_hdr.dest));
}

static void send_udp_packet(t_udp_packet *packet, t_worker *worker)
{
	int sent;

	if ((sent = sendto(worker->udp_socket, packet, sizeof(*packet) + worker->env->params.payload_size, 0, worker->env->dst_sockaddr, worker->env->dst_sockaddrlen)) == -1)
		ft_exit("sento failed, exiting", EXIT_FAILURE);
	printf("sent %d to port %d\n", sent, ntohs(packet->udp_hdr.dest));
}

static void send_syn_scan(t_worker *worker, t_port_result *port_result, t_scan_datas *scan_datas)
{
	t_tcp_packet packet;

	build_tcp_packet(&packet, worker, port_result, scan_datas);
	packet.tcp_hdr.syn = 1;
	packet.tcp_hdr.source = htons(SYN_PORT);
	packet.tcp_hdr.check = build_tcp_checksum(&packet, worker, port_result, scan_datas);
	send_tcp_packet(&packet, worker);
	scan_datas->last_scan = get_time();
	scan_datas->sent = 1;
}

static void send_null_scan(t_worker *worker, t_port_result *port_result, t_scan_datas *scan_datas)
{
	t_tcp_packet packet;

	build_tcp_packet(&packet, worker, port_result, scan_datas);
	packet.tcp_hdr.source = htons(NULL_PORT);
	packet.tcp_hdr.check = build_tcp_checksum(&packet, worker, port_result, scan_datas);
	send_tcp_packet(&packet, worker);
	scan_datas->last_scan = get_time();
	scan_datas->sent = 1;
}

static void send_ack_scan(t_worker *worker, t_port_result *port_result, t_scan_datas *scan_datas)
{
	t_tcp_packet packet;

	build_tcp_packet(&packet, worker, port_result, scan_datas);
	packet.tcp_hdr.ack = 1;
	packet.tcp_hdr.source = htons(ACK_PORT);
	packet.tcp_hdr.check = build_tcp_checksum(&packet, worker, port_result, scan_datas);
	send_tcp_packet(&packet, worker);
	scan_datas->last_scan = get_time();
	scan_datas->sent = 1;
}

static void send_fin_scan(t_worker *worker, t_port_result *port_result, t_scan_datas *scan_datas)
{
	t_tcp_packet packet;

	build_tcp_packet(&packet, worker, port_result, scan_datas);
	packet.tcp_hdr.fin = 1;
	packet.tcp_hdr.source = htons(FIN_PORT);
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
	packet.tcp_hdr.source = htons(XMAS_PORT);
	packet.tcp_hdr.check = build_tcp_checksum(&packet, worker, port_result, scan_datas);
	send_tcp_packet(&packet, worker);
	scan_datas->last_scan = get_time();
	scan_datas->sent = 1;
}

static void send_udp_scan(t_worker *worker, t_port_result *port_result, t_scan_datas *scan_datas)
{
	t_udp_packet packet;

	build_udp_packet(&packet, worker, port_result, scan_datas);
	packet.udp_hdr.source = htons(UDP_PORT);
	packet.udp_hdr.check = build_udp_checksum(&packet, worker, port_result, scan_datas);
	send_udp_packet(&packet, worker);
	scan_datas->last_scan = get_time();
	scan_datas->sent = 1;
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
	++scan_datas->retry;
}
