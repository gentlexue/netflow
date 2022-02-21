
#include <stdint.h>

#include <netinet/in.h>
#include <linux/if_ether.h>

#define MAX_SKIPLIST_DEPTH 10
extern unsigned char 	mac_addr[2][6];
extern uint32_t 		ip_addr[2];
extern struct rte_timer 		arp;
extern struct rte_mempool 		*mbuf_pool;

// typedef struct addr_table {
// 	unsigned char 	mac_addr[6];
// 	unsigned char 	dst_mac[ETH_ALEN];
// 	uint32_t		src_ip;
// 	uint32_t		dst_ip;
// 	uint16_t		port_id;
// 	uint32_t		shift;
// 	int 			is_fill;
// 	uint8_t			is_alive;
// }__attribute__((__aligned__(1))) addr_table_t;


enum rte_timer_type {
	SINGLE,
	PERIODICAL
};

union rte_timer_status {
	RTE_STD_C11
	struct {
		uint16_t state;  /**< Stop, pending, running, config. */
		int16_t owner;   /**< The lcore that owns the timer. */
	};
	uint32_t u32;            /**< To atomic-set status + owner. */
};

struct rte_timer;
typedef void (*rte_timer_cb_t)(struct rte_timer *, void *);

#define MAX_SKIPLIST_DEPTH 10
struct rte_timer
{
	uint64_t expire;       /**< Time when timer expire. */
	struct rte_timer *sl_next[MAX_SKIPLIST_DEPTH];
	volatile union rte_timer_status status; /**< Status of timer. */
	uint64_t period;       /**< Period of timer (0 if not periodic). */
	rte_timer_cb_t f;      /**< Callback function. */
	void *arg;             /**< Argument to callback function. */
};