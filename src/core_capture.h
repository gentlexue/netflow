#ifndef DPDKCAP_CORE_CAPTURE_H
#define DPDKCAP_CORE_CAPTURE_H

#include <stdint.h>
#include <stdbool.h>
/*引入ETH_ALEN*/
#include <linux/if_ether.h>
#include <rte_common.h>
#define DPDKCAP_CAPTURE_BURST_SIZE 256


/* Core configuration structures */
struct core_capture_config {
  struct rte_ring * ring;
  bool volatile * stop_condition;
  struct core_capture_stats * stats;
  uint8_t port;
  uint8_t queue;
};

/* Statistics structure */
struct core_capture_stats {
  int core_id;
  uint64_t packets; //Packets successfully enqueued
  uint64_t missed_packets; //Packets core could not enqueue
};

/* Launches a capture task */
int capture_core(const struct core_capture_config * config);

extern unsigned char 	mac_addr[2][6];
extern uint32_t 		ip_addr[2];
extern struct rte_timer 		arp;
extern struct rte_mempool 		*mbuf_pool;

typedef struct addr_table {
	unsigned char 	mac_addr[6];
	unsigned char 	dst_mac[ETH_ALEN];
	uint32_t		src_ip;
	uint32_t		dst_ip;
	uint16_t		port_id;
	uint32_t		shift;
	int 			is_fill;
	uint8_t			is_alive;
}__attribute__((__aligned__(1))) addr_table_t;

extern addr_table_t 	addr_table[65535];
#endif
