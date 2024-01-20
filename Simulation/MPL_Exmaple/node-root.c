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

#if !NETSTACK_CONF_WITH_IPV6 || !UIP_CONF_ROUTER || !UIP_IPV6_MULTICAST || !UIP_CONF_IPV6_RPL
#error "This example can not work with the current contiki configuration"
#error "Check the values of: NETSTACK_CONF_WITH_IPV6, UIP_CONF_ROUTER, UIP_CONF_IPV6_RPL"
#endif
/*---------------------------------------------------------------------------*/
PROCESS(rpl_root_process, "RPL ROOT, Multicast Sender");
AUTOSTART_PROCESSES(&rpl_root_process);
/*---------------------------------------------------------------------------*/
static void
set_own_addresses(void)
{
  int i;
  uint8_t state;
  rpl_dag_t *dag;
  uip_ipaddr_t ipaddr;

  uip_ip6addr(&ipaddr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0, 0, 0, 0);
  uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
  uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);

  PRINTF("Our IPv6 addresses:\n");
  for (i = 0; i < UIP_DS6_ADDR_NB; i++)
  {
    state = uip_ds6_if.addr_list[i].state;
    if (uip_ds6_if.addr_list[i].isused && (state == ADDR_TENTATIVE || state == ADDR_PREFERRED))
    {
      PRINTF("  ");
      PRINT6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
      PRINTF("\n");
      if (state == ADDR_TENTATIVE)
      {
        uip_ds6_if.addr_list[i].state = ADDR_PREFERRED;
      }
    }
  }

  /* Become root of a new DODAG with ID our global v6 address */
  dag = rpl_set_root(RPL_DEFAULT_INSTANCE, &ipaddr);
  if (dag != NULL)
  {
    rpl_set_prefix(dag, &ipaddr, 64);
    PRINTF("Created a new RPL dag with ID: ");
    PRINT6ADDR(&dag->dag_id);
    PRINTF("\n");
  }
  else
  {
    PRINTF("Couldn't create a new RPL dag with ID: ");
    PRINT6ADDR(&dag->dag_id);
    PRINTF("\n");
  }
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(rpl_root_process, ev, data)
{
  static struct etimer energy_log_timer;

  PROCESS_BEGIN();

  PRINTF("Multicast Engine: '%s'\n", UIP_MCAST6.name);

  set_own_addresses();

  etimer_set(&energy_log_timer, ENERGY_LOG_DELAY * CLOCK_SECOND);

  while (1)
  {

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

  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
