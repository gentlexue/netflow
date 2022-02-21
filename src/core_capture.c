#include <stdbool.h>
#include <signal.h>
#include <string.h>

#include <rte_log.h>
#include <rte_lcore.h>
#include <rte_ethdev.h>
#include <rte_version.h>

/*解析报文*/
#include <rte_branch_prediction.h>
#include <rte_ip.h>
#include <rte_icmp.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_arp.h>
#include <netinet/in.h>
#include <rte_ether.h>
#include <rte_flow.h>

#include "core_capture.h"
#include "producer.h"
#include "protocal.h"

#define RTE_LOGTYPE_DPDKCAP RTE_LOGTYPE_USER1

/* 定义报文协议 */
#define ARP 					0x0806
#define ICMP 					1
#define TCP 					0x6
#define UDP 					0X11


/*
 * Capture the traffic from the given port/queue tuple
 */
int capture_core(const struct core_capture_config * config) {
  struct rte_mbuf *bufs[DPDKCAP_CAPTURE_BURST_SIZE];
  uint16_t nb_rx;
  int nb_rx_enqueued;
  int i;

  struct rte_mbuf *single_pkt;
  struct ether_hdr *eth_hdr;
  struct ipv4_hdr 	*ip_hdr;
	struct icmp_hdr 	*icmphdr;
	struct udp_hdr 	*udphdr;
	struct tcp_hdr 	*tcphdr;
  struct arp_hdr 	*arphdr;
	unsigned char 		mac_addr[2][6];
	uint32_t 				ip_addr[2];
	uint32_t 			new_port_id;
  addr_table_t 	addr_table[65535];
  uint64_t 			total_tx;

  RTE_LOG(INFO, DPDKCAP, "Core %u is capturing packets for port %u\n",
      rte_lcore_id(), config->port);

  /* Init stats */
  *(config->stats) = (struct core_capture_stats) {
    .core_id=rte_lcore_id(),
    .packets = 0,
    .missed_packets = 0,
  };

  /* Run until the application is quit or killed. */
  for (;;) {
    /* Stop condition */
    if (unlikely(*(config->stop_condition))) {
      break;
    }

    /* Retrieve packets and put them into the ring */
    nb_rx = rte_eth_rx_burst(config->port, config->queue,
        bufs, DPDKCAP_CAPTURE_BURST_SIZE);
    if (likely(nb_rx > 0)) {
      RTE_LOG(NOTICE, DPDKCAP, "Enable kafka producer\n");
      int i ;
      for(i=0;i<nb_rx;i++){
        single_pkt=bufs[i];
        rte_prefetch0(rte_pktmbuf_mtod(single_pkt, void *));
        eth_hdr = rte_pktmbuf_mtod(single_pkt,struct ether_hdr*);

        if (eth_hdr->ether_type == rte_cpu_to_be_16(ARP)) {
				rte_memcpy(eth_hdr->d_addr.addr_bytes,eth_hdr->s_addr.addr_bytes,6);
				rte_memcpy(eth_hdr->s_addr.addr_bytes,mac_addr[0],6);
				arphdr = (struct arp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct ether_hdr));
				if (unlikely(arphdr->arp_op == rte_cpu_to_be_16(ARP_OP_REQUEST) && arphdr->arp_data.arp_tip == ip_addr[0])) {
					rte_memcpy(arphdr->arp_data.arp_tha.addr_bytes,arphdr->arp_data.arp_sha.addr_bytes,6);
					rte_memcpy(arphdr->arp_data.arp_sha.addr_bytes,mac_addr[0],6);
					arphdr->arp_data.arp_tip = arphdr->arp_data.arp_sip;
					arphdr->arp_data.arp_sip = ip_addr[0];
					arphdr->arp_op = rte_cpu_to_be_16(ARP_OP_REPLY);
					rte_eth_tx_burst(0,0,&single_pkt,1);
				}
				else
					rte_pktmbuf_free(single_pkt);
				continue;	
			}
      else {
				ip_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct ether_hdr));
				single_pkt->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM;
				single_pkt->l2_len = sizeof(struct ether_hdr);
				single_pkt->l3_len = sizeof(struct ipv4_hdr);
				ip_hdr->hdr_checksum = 0;
				printf("协议%d\n",ip_hdr->next_proto_id);
				switch (ip_hdr->next_proto_id) {
					case ICMP:
					 	icmphdr = (struct icmp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
						nat_icmp_learning(eth_hdr,ip_hdr,icmphdr,&new_port_id);
					 	addr_table[new_port_id].is_alive = 10;
					 	if (unlikely(addr_table[new_port_id].is_fill == 0)) {
							rte_pktmbuf_free(single_pkt);
							break;
						}
					 	rte_memcpy(eth_hdr->d_addr.addr_bytes,addr_table[new_port_id].dst_mac,6);
						rte_memcpy(eth_hdr->s_addr.addr_bytes,mac_addr[1],6);
						ip_hdr->src_addr = ip_addr[1];
						icmphdr->icmp_ident = rte_cpu_to_be_16(new_port_id);
						icmphdr->icmp_cksum = 0;
						icmphdr->icmp_cksum = get_checksum(icmphdr,single_pkt->data_len - sizeof(struct ipv4_hdr));
						  
						bufs[total_tx++] = single_pkt;
						puts("nat icmp at port 0");
						break;
					case UDP :
						single_pkt->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_UDP_CKSUM;

						udphdr = (struct udp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
						nat_udp_learning(eth_hdr,ip_hdr,udphdr,&new_port_id);
		 				addr_table[new_port_id].is_alive = 10;
						if (unlikely(addr_table[new_port_id].is_fill == 0)) {
							rte_pktmbuf_free(single_pkt);
							break;
						}
		 				rte_memcpy(eth_hdr->d_addr.addr_bytes,addr_table[new_port_id].dst_mac,6);
						rte_memcpy(eth_hdr->s_addr.addr_bytes,mac_addr[1],6);
						ip_hdr->src_addr = ip_addr[1];
						udphdr->src_port = rte_cpu_to_be_16(new_port_id);
						udphdr->dgram_cksum = 0;
						break;
					case TCP :
						single_pkt->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_TCP_CKSUM;
						tcphdr = (struct tcp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
						
						nat_tcp_learning(eth_hdr,ip_hdr,tcphdr,&new_port_id);
						addr_table[new_port_id].is_alive = 10;
						if (unlikely(addr_table[new_port_id].is_fill == 0)) {
							rte_pktmbuf_free(single_pkt);
							break;
						}
						rte_memcpy(eth_hdr->d_addr.addr_bytes,addr_table[new_port_id].dst_mac,6);
						rte_memcpy(eth_hdr->s_addr.addr_bytes,mac_addr[1],6);
						ip_hdr->src_addr = ip_addr[1];
						tcphdr->src_port = rte_cpu_to_be_16(new_port_id);
						tcphdr->cksum = 0;
						break;
					default:
						  rte_pktmbuf_free(single_pkt);
						  puts("recv other packet");
						;
				}
			
		}



      }
      
#if RTE_VERSION >= RTE_VERSION_NUM(17,5,0,16)
      nb_rx_enqueued = rte_ring_enqueue_burst(config->ring, (void*) bufs,
          nb_rx, NULL);
#else
      nb_rx_enqueued = rte_ring_enqueue_burst(config->ring, (void*) bufs,
          nb_rx);
#endif

      /* Update stats */
      if(nb_rx_enqueued == nb_rx) {
        config->stats->packets+=nb_rx;
      } else {
        config->stats->missed_packets+=nb_rx;
        /* Free whatever we can't put in the write ring */
        for (i=nb_rx_enqueued; i < nb_rx; i++) {
          rte_pktmbuf_free(bufs[i]);
        }
      }
    }
  }

  RTE_LOG(INFO, DPDKCAP, "Closed capture core %d (port %d)\n",
      rte_lcore_id(), config->port);

  return 0;
}
