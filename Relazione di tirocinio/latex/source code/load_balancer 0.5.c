

// aggiunte personali
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
// aggiunte personali

#include <utils.h>
#include <arg_parser.h>
#include <flow_offload.h>
#include <dpi_worker.h>

#include "dns_filter_core.h"

#include <doca_dpi.h>
#include <utils.h>
#include <rte_sft.h>

#include <stdbool.h>
#include <unistd.h>

#include <doca_log.h>

#include <rte_hash.h>
#include <rte_fbk_hash.h>
#include <rte_jhash.h>
#include <rte_hash_crc.h>

DOCA_LOG_REGISTER(DPI_SCAN);

#define PACKET_BURST 1024

struct ipv4_5tuple
{
	uint32_t ip_src;
	uint32_t ip_dst;
	uint16_t port_src;
	uint16_t port_dst;
	uint8_t proto;
};

static struct rte_hash_parameters ut_params = {
	.entries = 64,
	.key_len = sizeof(struct ipv4_5tuple),
	.hash_func = rte_jhash,
	.hash_func_init_val = 0,
	.socket_id = 0,
};

static struct doca_dpi_ctx *dpi_ctx;

void extract_tuple(struct ipv4_5tuple *tuple, struct doca_dpi_parsing_info parsing_info);
void print_tuple(struct ipv4_5tuple tuple);
void load_balancer_init();

void scan(unsigned int nb_queues, unsigned int nb_ports, struct rte_hash *hashtable;);

static void
handle_packets_received(uint16_t packets_received, struct rte_mbuf **packets, struct rte_hash *hashtable);

int dpi_scan(struct rte_mbuf *packet, struct doca_dpi_parsing_info *parsing_info,
			 uint32_t *payload_offset);

static int
set_l4_parsing_info(struct doca_dpi_parsing_info *parsing_info, uint32_t *payload_offset,
					const struct rte_sft_mbuf_info *mbuf_info);

int main(int argc, char **argv)
{
	struct application_dpdk_config dpdk_config = {
		.port_config.nb_ports = 2,
		.port_config.nb_queues = 2,
		.port_config.nb_hairpin_q = 4,
		.sft_config = {0},
	};

	/* init and start parsing */
	struct doca_program_general_config *doca_general_config;
	struct doca_program_type_config type_config = {
		.is_dpdk = true,
		.is_grpc = false,
	};

	/* Parse cmdline/json arguments */
	arg_parser_init("dns_filter", &type_config, NULL);
	arg_parser_start(argc, argv, &doca_general_config);

	struct rte_hash *hashtable;
	ut_params.name = "test1";
	hashtable = rte_hash_create(&ut_params);
	if (hashtable == NULL)
		rte_panic("Failed to create cdev_map hash table, errno = %d\n", rte_errno);

	/* update queues and ports */
	dpdk_init(&dpdk_config);

	load_balancer_init();

	scan(dpdk_config.port_config.nb_queues, dpdk_config.port_config.nb_ports, hashtable);

	return 0;
}

void load_balancer_init()
{
	char cdo_filename[] = "/tmp/signatures.cdo";
	int err, ret;

	struct doca_dpi_config_t doca_dpi_config = {
		/* Total number of DPI queues */
		.nb_queues = 1,
		/* Maximum job size in bytes for regex scan match */
		.max_sig_match_len = 5000,
		/* Max amount of FIDS per DPI queue */
		.max_packets_per_queue = 100,
	};

	/* Initialization of DPI library */
	dpi_ctx = doca_dpi_init(&doca_dpi_config, &err);
	if (err < 0)
	{
		APP_EXIT("DPI init failed");
	}

	/* Load signatures into regex device */
	ret = doca_dpi_load_signatures(dpi_ctx, cdo_filename);
	if (ret < 0)
	{
		APP_EXIT("Loading DPI signatures failed, error=%d", ret);
	}
}

void scan(unsigned int nb_queues, unsigned int nb_ports, struct rte_hash *hashtable)
{

	struct rte_mbuf *packets[PACKET_BURST];
	uint16_t nb_packets, queue;
	uint8_t ingress_port;

	while (1)
	{
		for (ingress_port = 0; ingress_port < nb_ports; ingress_port++)
		{
			for (queue = 0; queue < nb_queues; queue++)
			{
				/* Get number of packets received on rx queue */
				nb_packets = rte_eth_rx_burst(ingress_port, queue, packets, PACKET_BURST);

				/* Check if packets received and handle them */
				if (nb_packets)
					handle_packets_received(nb_packets, packets, hashtable);
			}
		}
	}
}

static void
handle_packets_received(uint16_t packets_received, struct rte_mbuf **packets, struct rte_hash *hashtable)
{
	struct rte_mbuf *packet = NULL;
	uint16_t queue_id = 0;
	uint8_t egress_port = 0;
	uint32_t current_packet = 0;
	struct ipv4_5tuple tuple = {0};

	int sid;
	int32_t ret = 0;

	for (current_packet = 0; current_packet < packets_received; current_packet++)
	{

		sid = 0;
		uint32_t payload_offset = 0;
		struct rte_sft_mbuf_info mbuf_info = {0};
		struct doca_dpi_parsing_info parsing_info = {0};
		struct rte_sft_error error;

		packet = packets[current_packet];

		rte_sft_parse_mbuf(packet, &mbuf_info, NULL, &error);
		set_l4_parsing_info(&parsing_info, &payload_offset, &mbuf_info);

		extract_tuple(&tuple, parsing_info);
		print_tuple(tuple);

		ret = rte_hash_lookup_data(hashtable, &tuple, (void **)&sid);

		if (ret == -ENOENT)
		{
			// DOCA_LOG_INFO("tupla non presente");
			DOCA_LOG_INFO("DPI scan");
			sid = dpi_scan(packet, &parsing_info, &payload_offset);
			if (sid)
				ret = rte_hash_add_key_data(hashtable, &tuple, (void *)sid);
		}
		else
		{
			// DOCA_LOG_INFO("tupla presente valore:%d", sid);
		}

		if (sid == 1)
			egress_port = packet->port ^ 1;
		else
			egress_port = packet->port;

		rte_eth_tx_burst(egress_port, queue_id, &packets[current_packet], 1);
	}
}

void print_tuple(struct ipv4_5tuple tuple)
{
	char *src_adrr;
	struct in_addr ip_src;
	struct in_addr ip_dst;
	char buffer[18];

	ip_dst.s_addr = tuple.ip_dst;
	memcpy(buffer, inet_ntoa(ip_dst), strlen(inet_ntoa(ip_dst)) + 1);

	ip_src.s_addr = tuple.ip_src;
	src_adrr = inet_ntoa(ip_src);

	DOCA_LOG_INFO("Packet info [src:%s,dst:%s,src:%hu,dst:%hu,proto:%hu]", src_adrr, buffer, ntohs(tuple.port_src), ntohs(tuple.port_dst), tuple.proto);
}

void extract_tuple(struct ipv4_5tuple *tuple, struct doca_dpi_parsing_info parsing_info)
{
	tuple->ip_dst = parsing_info.dst_ip.ipv4.s_addr;
	tuple->ip_src = parsing_info.src_ip.ipv4.s_addr;
	tuple->port_src = parsing_info.l4_sport;
	tuple->port_dst = parsing_info.l4_dport;
	tuple->proto = parsing_info.l4_protocol;
}

int dpi_scan(struct rte_mbuf *packet, struct doca_dpi_parsing_info *parsing_info,
			 uint32_t *payload_offset)
{
	bool to_server = true;

	int err, ret;
	int packets_to_process = 0;
	uint16_t dpi_queue = 0;
	struct doca_dpi_sig_data sig_data;

	struct doca_dpi_flow_ctx *flow_ctx = NULL;
	struct doca_dpi_result result = {0};
	struct doca_dpi_stat_info stats = {0};

	/* Create DPI flow according to packet info */
	flow_ctx = doca_dpi_flow_create(dpi_ctx, dpi_queue, parsing_info, &err, &result);
	if (err < 0)
	{
		DOCA_LOG_ERR("DPI flow creation failed, error=%d", err);
		return err;
	}

	ret = doca_dpi_enqueue(flow_ctx, packet, to_server, *payload_offset, NULL);
	if (ret == DOCA_DPI_ENQ_PROCESSING || ret == DOCA_DPI_ENQ_BUSY)
		packets_to_process = 1;
	else if (ret < 0)
	{
		DOCA_LOG_ERR("DPI enqueue failed, error=%d", ret);
		return ret;
	}

	while (packets_to_process > 0)
	{
		if (doca_dpi_dequeue(dpi_ctx, dpi_queue, &result) == DOCA_DPI_DEQ_READY)
		{
			packets_to_process -= 1;
			if (result.matched)
			{
				ret = doca_dpi_signature_get(dpi_ctx, result.info.sig_id,
											 &sig_data);
				if (ret < 0)
				{
					DOCA_LOG_ERR("Failed to get signatures - error=%d", ret);
					return ret;
				}
				DOCA_LOG_INFO(
					"DPI found a match on signature with ID: %u and URL MSG: %s\n",
					result.info.sig_id, sig_data.name);
			}
		}
	}
	/*
	doca_dpi_stat_get(dpi_ctx, true, &stats);
	DOCA_LOG_INFO("------------- DPI STATISTICS --------------");
	DOCA_LOG_INFO("Packets scanned:%d", stats.nb_scanned_pkts);
	DOCA_LOG_INFO("Matched signatures:%d", stats.nb_matches);
	DOCA_LOG_INFO("TCP matches:%d", stats.nb_tcp_based);
	DOCA_LOG_INFO("UDP matches:%d", stats.nb_udp_based);
	DOCA_LOG_INFO("HTTP matches:%d \n\n", stats.nb_http_parser_based);
	*/
	return result.info.sig_id;
}

static int
set_l4_parsing_info(struct doca_dpi_parsing_info *parsing_info, uint32_t *payload_offset,
					const struct rte_sft_mbuf_info *mbuf_info)
{
	*payload_offset += ((mbuf_info->l4_hdr - (void *)mbuf_info->eth_hdr));
	parsing_info->ethertype = rte_cpu_to_be_16(mbuf_info->eth_type);
	parsing_info->l4_protocol = mbuf_info->l4_protocol;

	if (!mbuf_info->is_ipv6)
	{
		parsing_info->dst_ip.ipv4.s_addr = mbuf_info->ip4->dst_addr;
		parsing_info->src_ip.ipv4.s_addr = mbuf_info->ip4->src_addr;
	}
	else
		memcpy(&parsing_info->dst_ip.ipv6, &mbuf_info->ip6->dst_addr[0], 16);
	switch (parsing_info->l4_protocol)
	{
	case IPPROTO_UDP:
		*payload_offset += 8;
		parsing_info->l4_sport = mbuf_info->udp->src_port;
		parsing_info->l4_dport = mbuf_info->udp->dst_port;
		break;
	case IPPROTO_TCP:
		*payload_offset += ((struct rte_tcp_hdr *)mbuf_info->l4_hdr)->data_off / 4;
		parsing_info->l4_sport = mbuf_info->tcp->src_port;
		parsing_info->l4_dport = mbuf_info->tcp->dst_port;
		break;
	default:
		DOCA_LOG_DBG("Unsupported L4 protocol!");
		return -1;
	}

	/*
	char *some_addr;
	some_addr = inet_ntoa(parsing_info->dst_ip.ipv4);
	printf("\nIpv4 destination address in network byte order: %s\n", some_addr);


	some_addr = inet_ntoa(parsing_info->src_ip.ipv4);
	printf("\nIpv4 source address in network byte order: %s\n", some_addr);

	printf("Ethertype of the packet in network byte order hex: 0x%04x\n", ntohs(parsing_info->ethertype));
	printf("Layer 4 destination port in network byte order: %hu\n", ntohs(parsing_info->l4_dport));
	printf("Layer 4 protocol: %hu\n", parsing_info->l4_protocol);
	printf("Layer 4 source port in network byte order: %hu\n", ntohs(parsing_info->l4_sport));
	*/

	return 0;
}