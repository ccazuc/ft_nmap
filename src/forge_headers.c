#include "ft_nmap.h"

void forge_tcp_hdr(struct tcphdr *tcp_hdr, t_worker *worker, t_port_result *port_result, t_scan_datas *scan_datas)
{
	ft_memset(tcp_hdr, 0, sizeof(*tcp_hdr));
	tcp_hdr->source = htons(worker->env->params.host_port);
	tcp_hdr->dest = htons(port_result->port);
	tcp_hdr->seq = 0;
	tcp_hdr->ack_seq = 0;
	tcp_hdr->doff = (sizeof(*tcp_hdr) * 8) / 32;
	tcp_hdr->fin = 0;
	tcp_hdr->syn = 0;
	tcp_hdr->rst = 0;
	tcp_hdr->psh = 0;
	tcp_hdr->ack = 0;
	tcp_hdr->urg = 0;
	tcp_hdr->check = 0;
	tcp_hdr->urg_ptr = 0;
	tcp_hdr->window = htons(128);
}

void forge_ip_hdr(struct ip *ip_hdr, t_worker *worker)
{
	ip_hdr->ip_v = 4;
	ip_hdr->ip_hl = 5;
	ip_hdr->ip_tos = IPTOS_LOWDELAY;
	ip_hdr->ip_len = 0;
	ip_hdr->ip_id = 0;
	ip_hdr->ip_off = ntohs(IP_DF);
	ip_hdr->ip_ttl = 0xFF;
	ip_hdr->ip_p = 0;
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_src.s_addr = 0;
	ip_hdr->ip_dst = *worker->env->dst_bin;
}

static uint16_t compute_checksum(char *datas, int32_t len)
{
	uint64_t sum;
	int32_t i;
	uint16_t *packet;

	i = -1;
	sum = 0;
	packet = (uint16_t*)datas;
	while (++i < len / 2)
		sum += packet[i];
	if (i * 2 < len)
		sum += packet[i] & 0x00FF;
	while (sum > 0xFFFF)
		sum = (sum & 0xFFFF) + (sum >> 16);
	return ~sum;
}

uint16_t build_tcp_checksum(t_tcp_packet *tcp_packet, t_worker *worker, t_port_result *port_result, t_scan_datas *scan_datas)
{
	t_tcp_pseudo_hdr pseudo_hdr;
	char *checksum_datas;

	pseudo_hdr.src = worker->env->src_s_addr;
	pseudo_hdr.dst = worker->env->dst_bin->s_addr;
	pseudo_hdr.reserved = 0;
	pseudo_hdr.prot = tcp_packet->ip_hdr.ip_p;
	pseudo_hdr.len = htons(sizeof(tcp_packet->tcp_hdr) + worker->env->params.payload_size);
	if (!(checksum_datas = malloc(sizeof(pseudo_hdr) + sizeof(tcp_packet->tcp_hdr) + worker->env->params.payload_size)))
		ft_exit("Error, could not malloc tcp header", EXIT_FAILURE);
	memcpy(checksum_datas, &pseudo_hdr, sizeof(pseudo_hdr));
	memcpy(checksum_datas + sizeof(pseudo_hdr), ((unsigned char*)tcp_packet) + sizeof(tcp_packet->ip_hdr), sizeof(tcp_packet->tcp_hdr) + worker->env->params.payload_size);
	return compute_checksum(checksum_datas, sizeof(pseudo_hdr) + sizeof(tcp_packet->tcp_hdr) + worker->env->params.payload_size);
}

void build_tcp_packet(t_tcp_packet *tcp_packet, t_worker *worker, t_port_result *port_result, t_scan_datas *scan_datas)
{
	forge_ip_hdr(&tcp_packet->ip_hdr, worker);
	forge_tcp_hdr(&tcp_packet->tcp_hdr, worker, port_result, scan_datas);
	tcp_packet->ip_hdr.ip_p = IPPROTO_TCP;
}
