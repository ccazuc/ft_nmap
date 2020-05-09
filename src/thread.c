#include "ft_nmap.h"

static void check_timeout_scans(t_worker *worker, t_port_result *port_result, t_scan_datas *scan_datas)
{
	port_result->finished = 1;
	//printf("a\n");
	for (uint8_t i = 0; i < worker->env->number_diff_scans; ++i)
	{
		printf("\n\ntype %d\n", scan_datas[i].type);
		if (scan_datas[i].finished || !scan_datas[i].last_scan)
		{
			printf("finished %d last_scan %ld\n", scan_datas[i].finished, scan_datas[i].last_scan);
			continue;
		}
		if ((get_time() - scan_datas[i].last_scan) / 1000 >= worker->env->params.scan_timeout)
		{
			if (scan_datas[i].retry >= worker->env->params.scan_max_retry)
				scan_datas[i].finished = 1;
			scan_datas[i].sent = 0;
			printf("%ld\n", (get_time() - scan_datas[i].last_scan) / 1000);
			continue;
		}
		printf("set 0\n");
		port_result->finished = 0;
	}
}

static void send_scans(t_worker *worker, t_port_result *port_result)
{
	t_scan_datas *scan_datas = port_result->scans;
	for (uint8_t i = 0; i < worker->env->number_diff_scans; ++i)
	{
		if (scan_datas[i].sent || scan_datas[i].finished)
			continue;
		send_scan(worker, port_result, &scan_datas[i]);
	}
}

static void handle_syn_scan(t_worker *worker, t_tcp_packet *packet, t_scan_datas *scan_datas)
{
	printf("received syn\n");
	if (packet->tcp_hdr.syn == 1 && packet->tcp_hdr.ack == 1)
	{
		scan_datas->state = STATE_OPEN;
	}
	else
	{
		scan_datas->state = STATE_CLOSED;
	}
	scan_datas->finished = 1;
}

static void handle_null_scan(t_worker *worker, t_tcp_packet *packet, t_scan_datas *scan_datas)
{
	if (packet->tcp_hdr.rst == 1 && packet->tcp_hdr.ack == 1)
	{
		scan_datas->state = STATE_CLOSED;
		printf("received null\n");
	}
	scan_datas->finished = 1;
}

static void handle_ack_scan(t_worker *worker, t_tcp_packet *packet, t_scan_datas *scan_datas)
{
	(void)worker;
	(void)packet;
	(void)scan_datas;
}

static void handle_fin_scan(t_worker *worker, t_tcp_packet *packet, t_scan_datas *scan_datas)
{
	if (packet->tcp_hdr.rst == 1 && packet->tcp_hdr.ack == 1)
	{
		printf("received fin\n");
		scan_datas->state = STATE_CLOSED;
	}
	scan_datas->finished = 1;
}

static void handle_xmas_scan(t_worker *worker, t_tcp_packet *packet, t_scan_datas *scan_datas)
{
	if (packet->tcp_hdr.rst == 1 && packet->tcp_hdr.ack == 1)
	{
		printf("received xmas\n");
		scan_datas->state = STATE_CLOSED;
	}
	scan_datas->finished = 1;
}

static void handle_tcp_packet(t_tcp_packet *packet, t_worker *worker)
{
	for (uint16_t i = 0; i < worker->env->ports_per_thread && worker->ports_result[i].port <= worker->env->params.max_port; ++i)
	{
		if (worker->ports_result[i].port != ntohs(packet->tcp_hdr.source))
			continue;
		for (uint8_t j = 0; j < worker->env->number_diff_scans; ++j)
		{
			if (worker->ports_result[i].scans[j].type == SCAN_SYN && ntohs(packet->tcp_hdr.ack_seq) == SYN_SEQ)
				handle_syn_scan(worker, packet, &worker->ports_result[i].scans[j]);
			else if (worker->ports_result[i].scans[j].type == SCAN_NULL && ntohs(packet->tcp_hdr.ack_seq) == NULL_SEQ)
				handle_null_scan(worker, packet, &worker->ports_result[i].scans[j]);
			else if (worker->ports_result[i].scans[j].type == SCAN_ACK && ntohs(packet->tcp_hdr.ack_seq) == ACK_SEQ)
				handle_ack_scan(worker, packet, &worker->ports_result[i].scans[j]);
			else if (worker->ports_result[i].scans[j].type == SCAN_FIN && ntohs(packet->tcp_hdr.ack_seq) == FIN_SEQ)
				handle_fin_scan(worker, packet, &worker->ports_result[i].scans[j]);
			else if (worker->ports_result[i].scans[j].type == SCAN_XMAS && ntohs(packet->tcp_hdr.ack_seq) == XMAS_SEQ)
				handle_xmas_scan(worker, packet, &worker->ports_result[i].scans[j]);
		}
	}
}

static void receive_tcp_packet(t_worker *worker)
{
	t_tcp_packet packet;
	int received;

	printf("receiving\n");
	if ((received = recvfrom(worker->tcp_socket, &packet, sizeof(packet), 0, NULL, NULL)) <= 0)
	{
		if (!received)
			return;
		ft_exit("Error, could not receive tcp packet", EXIT_FAILURE);
	}
	if ((uint32_t)received < sizeof(packet))
		return;
	printf("received %d | syn %d, ack %d, fin %d, rst %d, seq %d, ack_seq %d, dst %d, src %d\n", received, packet.tcp_hdr.syn, packet.tcp_hdr.ack, packet.tcp_hdr.fin, packet.tcp_hdr.rst, ntohs(packet.tcp_hdr.seq), ntohs(packet.tcp_hdr.ack_seq), ntohs(packet.tcp_hdr.dest), ntohs(packet.tcp_hdr.source));
	handle_tcp_packet(&packet, worker);
}

static void receive_packets(t_worker *worker)
{
	receive_tcp_packet(worker);
}

static void check_ports_finished(t_worker *worker)
{
	worker->running = 0;
	for (uint16_t i = 0; i < worker->env->ports_per_thread && worker->ports_result[i].port <= worker->env->params.max_port; ++i)
	{
		if (!worker->ports_result[i].finished)
		{
			worker->running = 1;
			return;
		}
	}
}

static void *thread_run(void *ptr)
{
	t_worker *worker = ptr;
	t_env *env = worker->env;

	create_sockets(worker);
	worker->running = 1;
	while (worker->running)
	{
		for (uint16_t i = 0; i < env->ports_per_thread && worker->ports_result[i].port <= env->params.max_port; ++i)
		{
			send_scans(worker, &worker->ports_result[i]);
			printf("port %d\n", worker->ports_result[i].port);
			check_timeout_scans(worker, &worker->ports_result[i], worker->ports_result[i].scans);
		}
		receive_packets(worker);
		check_ports_finished(worker);
	}
	printf("THREAD FINISHED\n");
	return NULL;
}

void create_threads(t_env *env)
{
	if (!(env->threads = malloc(sizeof(*env->threads) * env->params.num_threads)))
		ft_exit("Error, could not malloc threads", EXIT_FAILURE);
	env->ports_per_thread = (uint16_t)(ceil((1 + env->params.max_port - env->params.min_port) / (float)env->params.num_threads));
	for (uint8_t i = 0; i < env->params.num_threads; ++i)
	{
		if (!(env->threads[i].ports_result = malloc(sizeof(*env->threads[i].ports_result) * env->ports_per_thread)))
			ft_exit("Error, could not malloc ports_result", EXIT_FAILURE);
		for (uint16_t j = 0; j < env->ports_per_thread; ++j)
		{
			if (!(env->threads[i].ports_result[j].scans = malloc(sizeof(*env->threads[i].ports_result[j].scans) * env->number_diff_scans)))
				ft_exit("Error, could not malloc scans", EXIT_FAILURE);
			for (uint8_t k = 0; k < env->number_diff_scans; ++k)
			{
				env->threads[i].ports_result[j].scans[k].type = env->scan_list[k];
				env->threads[i].ports_result[j].scans[k].last_scan = 0;
				env->threads[i].ports_result[j].scans[k].retry = 0;
				if (env->scan_list[k] == SCAN_SYN || env->scan_list[k] == SCAN_ACK)
					env->threads[i].ports_result[j].scans[k].state = STATE_FILTERED;
				else if (env->scan_list[k] == SCAN_NULL || env->scan_list[k] == SCAN_FIN || env->scan_list[k] == SCAN_MAX)
					env->threads[i].ports_result[j].scans[k].state = STATE_OPEN_FILTERED;
				env->threads[i].ports_result[j].scans[k].finished = 0;
				env->threads[i].ports_result[j].scans[k].sent = 0;
			}
			env->threads[i].ports_result[j].port = env->params.min_port + env->ports_per_thread * i + j;
			env->threads[i].ports_result[j].finished = 0;
			printf("port %d\n", env->threads[i].ports_result[j].port);
		}
		env->threads[i].start_port = env->params.min_port + env->ports_per_thread * i;
		env->threads[i].end_port = env->params.min_port + env->ports_per_thread * (i + i);
		env->threads[i].env = env;
		if (pthread_create(&env->threads[i].thread, NULL, thread_run, &env->threads[i]))
			ft_exit("Error, could not create thread", EXIT_FAILURE);
	}
}