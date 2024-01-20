#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/ipv6/multicast/uip-mcast6.h"
#include "sys/node-id.h"

#include <string.h>

#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"
#include "net/rpl/rpl.h"

#include "sys/energest.h"

#define ENERGY_LOG_DELAY 295

#define MAX_PAYLOAD_LEN 120
#define MCAST_SINK_UDP_PORT 3001 /* Host byte order */
#define SEND_INTERVAL   15*CLOCK_SECOND /* clock ticks */
#define ITERATIONS 10 /* messages */

/* Start sending messages START_DELAY secs after we start so that routing can
 * converge and the mcast routing also  */
#define START_DELAY 60

static struct uip_udp_conn * mcast_conn;
static char buf[MAX_PAYLOAD_LEN];
static uint32_t seq_id;

#if !NETSTACK_CONF_WITH_IPV6 || !UIP_CONF_ROUTER || !UIP_IPV6_MULTICAST || !UIP_CONF_IPV6_RPL
#error "This example can not work with the current contiki configuration"
#error "Check the values of: NETSTACK_CONF_WITH_IPV6, UIP_CONF_ROUTER, UIP_CONF_IPV6_RPL"
#endif
/*---------------------------------------------------------------------------*/
PROCESS(rpl_root_process, "RPL ROOT, Multicast Sender");
AUTOSTART_PROCESSES(&rpl_root_process);
/*---------------------------------------------------------------------------*/
static void
multicast_send(void)
{
  uint32_t id;

  id = uip_htonl(seq_id);
  memset(buf, 0, MAX_PAYLOAD_LEN);
  memcpy(buf, &id, sizeof(seq_id));

  PRINTF("Send new Mcast paquet !!\n");

  seq_id++;
  uip_udp_packet_send(mcast_conn, buf, sizeof(id)); // size of data sent
}
/*---------------------------------------------------------------------------*/
static void
prepare_mcast(void)
{
  uip_ipaddr_t ipaddr;

  #if UIP_MCAST6_CONF_ENGINE == UIP_MCAST6_ENGINE_MPL
/*
 * MPL defines a well-known MPL domain, MPL_ALL_FORWARDERS, which
 *  MPL nodes are automatically members of. Send to that domain.
 */
  uip_ip6addr(&ipaddr, 0xFF03,0,0,0,0,0,0,0xFC);
#else
  /*
   * IPHC will use stateless multicast compression for this destination
   * (M=1, DAC=0), with 32 inline bits (1E 89 AB CD)
   */
  uip_ip6addr(&ipaddr, 0xFF1E,0,0,0,0,0,0x89,0xABCD);
#endif
  mcast_conn = udp_new(&ipaddr, UIP_HTONS(MCAST_SINK_UDP_PORT), NULL);
}
/*---------------------------------------------------------------------------*/
static void
set_own_addresses(void)
{
  int i;
  uint8_t state;
  //rpl_dag_t *dag;
  uip_ipaddr_t ipaddr;

  uip_ip6addr(&ipaddr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0, 0, 0, 0);
  uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
  uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);

  PRINTF("Our IPv6 addresses:\n");
  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(uip_ds6_if.addr_list[i].isused && (state == ADDR_TENTATIVE || state
        == ADDR_PREFERRED)) {
      PRINTF("  ");
      PRINT6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
      PRINTF("\n");
      if(state == ADDR_TENTATIVE) {
        uip_ds6_if.addr_list[i].state = ADDR_PREFERRED;
      }
    }
  }

}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(rpl_root_process, ev, data)
{
  static struct etimer energy_log_timer;

  static struct etimer et;

  PROCESS_BEGIN();

  PRINTF("Multicast Engine: '%s'\n", UIP_MCAST6.name);

  set_own_addresses();

  prepare_mcast();

  etimer_set(&energy_log_timer, ENERGY_LOG_DELAY * CLOCK_SECOND);
  
  etimer_set(&et, START_DELAY * CLOCK_SECOND);

  while(1) {

    if (etimer_expired(&energy_log_timer))
    {
      energest_flush();

      printf("CPU,%4lu,%4lu,%4lu\n",
             energest_type_time(ENERGEST_TYPE_CPU),
             energest_type_time(ENERGEST_TYPE_LPM),
             energest_type_time(ENERGEST_TYPE_MAX));
      printf("RADIO,%4lu,%4lu,%4lu\n",
             energest_type_time(ENERGEST_TYPE_LISTEN),
             energest_type_time(ENERGEST_TYPE_TRANSMIT),
             energest_type_time(ENERGEST_TYPE_MAX) - energest_type_time(ENERGEST_TYPE_TRANSMIT) - energest_type_time(ENERGEST_TYPE_LISTEN));

    etimer_set(&energy_log_timer, ENERGY_LOG_DELAY * CLOCK_SECOND);  
    }

    PROCESS_YIELD();
    if(etimer_expired(&et)) {
      if(seq_id == ITERATIONS) {
        etimer_stop(&et);
      } else {
        multicast_send();
        etimer_set(&et, SEND_INTERVAL);
      }
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
