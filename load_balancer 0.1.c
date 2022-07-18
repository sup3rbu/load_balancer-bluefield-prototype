/*
 * Copyright (c) 2021 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

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
DOCA_LOG_REGISTER(DPI_SCAN);

#define PACKET_BURST 1024

/*
 *  The main function, which does initialization
 *  of the rules and starts the process of filtering the DNS packets.
 */
static void
handle_packets_received(uint16_t packets_received, struct rte_mbuf **packets);

void scan(unsigned int nb_queues, unsigned int nb_ports);

static int
set_l4_parsing_info(struct doca_dpi_parsing_info *parsing_info, uint32_t *payload_offset,
					const struct rte_sft_mbuf_info *mbuf_info)
{
	*payload_offset += ((mbuf_info->l4_hdr - (void *)mbuf_info->eth_hdr));
	parsing_info->ethertype = rte_cpu_to_be_16(mbuf_info->eth_type);
	parsing_info->l4_protocol = mbuf_info->l4_protocol;

	if (!mbuf_info->is_ipv6)
		parsing_info->dst_ip.ipv4.s_addr = mbuf_info->ip4->dst_addr;
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
	return 0;
}
int dpi_scan(struct rte_mbuf *packet, struct doca_dpi_parsing_info *parsing_info,
			 uint32_t *payload_offset);

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

	/* update queues and ports */
	dpdk_init(&dpdk_config);

	scan(dpdk_config.port_config.nb_queues, dpdk_config.port_config.nb_ports);
	return 0;

	/* init dns filter */
	dns_filter_init(&dpdk_config);

	/* process packets */
	process_packets(dpdk_config.port_config.nb_queues, dpdk_config.port_config.nb_ports);

	/* closing and releasing resources */
	dns_filter_cleanup(dpdk_config.port_config.nb_ports);

	// return 0;
}

int dpi_scan(struct rte_mbuf *packet, struct doca_dpi_parsing_info *parsing_info,
			 uint32_t *payload_offset)
{
	bool to_server = true;
	char cdo_filename[] = "/tmp/signatures.cdo";
	int err, ret;
	int packets_to_process = 0;
	uint16_t dpi_queue = 0;
	struct doca_dpi_sig_data sig_data;
	struct doca_dpi_ctx *dpi_ctx = NULL;
	struct doca_dpi_flow_ctx *flow_ctx = NULL;
	struct doca_dpi_result result = {0};
	struct doca_dpi_stat_info stats = {0};
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
		DOCA_LOG_ERR("DPI init failed, error=%d", err);
		return err;
	}

	/* Load signatures into regex device */
	ret = doca_dpi_load_signatures(dpi_ctx, cdo_filename);
	if (ret < 0)
	{
		DOCA_LOG_ERR("Loading DPI signatures failed, error=%d", ret);
		return ret;
	}

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
					"DPI found a match on signature with ID: %u and URL MSG: %s",
					result.info.sig_id, sig_data.name);
			}
		}
	}

	doca_dpi_stat_get(dpi_ctx, true, &stats);

	DOCA_LOG_INFO("------------- DPI STATISTICS --------------");
	DOCA_LOG_INFO("Packets scanned:%d", stats.nb_scanned_pkts);
	DOCA_LOG_INFO("Matched signatures:%d", stats.nb_matches);
	DOCA_LOG_INFO("TCP matches:%d", stats.nb_tcp_based);
	DOCA_LOG_INFO("UDP matches:%d", stats.nb_udp_based);
	DOCA_LOG_INFO("HTTP matches:%d", stats.nb_http_parser_based);

	doca_dpi_destroy(dpi_ctx);

	return 0;
}
static void
handle_packets_received(uint16_t packets_received, struct rte_mbuf **packets)
{
	struct rte_mbuf *packet = NULL;
	uint16_t queue_id = 0;
	uint8_t ingress_port;
	uint32_t current_packet;


	for (current_packet = 0; current_packet < packets_received; current_packet++) {

		uint32_t payload_offset = 0;
		struct rte_sft_mbuf_info mbuf_info = {0};
		struct doca_dpi_parsing_info parsing_info = {0};
		struct rte_sft_error error;

		packet = packets[current_packet];

		rte_sft_parse_mbuf(packet, &mbuf_info, NULL, &error);
		set_l4_parsing_info(&parsing_info, &payload_offset, &mbuf_info);

		dpi_scan(&packet,&parsing_info,&payload_offset);

		/* Deciding the port to send the packet to */
		ingress_port = packet->port ^ 1;
		print_l4_header(packet);

	}

	/* Packet sent to port 0 or 1*/
	rte_eth_tx_burst(ingress_port, queue_id, packets, packets_received);
}

void scan(unsigned int nb_queues, unsigned int nb_ports)
{

	struct rte_mbuf *packets[PACKET_BURST];
	uint16_t nb_packets, queue;
	uint8_t ingress_port;

	while (1) {
		for (ingress_port = 0; ingress_port < nb_ports; ingress_port++) {
			for (queue = 0; queue < nb_queues; queue++) {
				/* Get number of packets received on rx queue */
				nb_packets =
				    rte_eth_rx_burst(ingress_port, queue, packets, PACKET_BURST);

				/* Check if packets received and handle them */
				if (nb_packets)
					handle_packets_received(nb_packets, packets);
			}


		}
	}

	return;
}
