#include "contiki.h"
#include "contiki-net.h"
#include "net/ipv6/multicast/uip-mcast6.h"
#include "sys/node-id.h"

#include <string.h>

#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

#include "sys/energest.h"

#define ENERGY_LOG_DELAY 295 // (>98% du temps de simulation)

#if !NETSTACK_CONF_WITH_IPV6 || !UIP_CONF_ROUTER || !UIP_IPV6_MULTICAST || !UIP_CONF_IPV6_RPL
#error "This example can not work with the current contiki configuration"
#error "Check the values of: NETSTACK_CONF_WITH_IPV6, UIP_CONF_ROUTER, UIP_CONF_IPV6_RPL"
#endif
/*---------------------------------------------------------------------------*/
PROCESS(mcast_intermediate_process, "Intermediate Process");
AUTOSTART_PROCESSES(&mcast_intermediate_process);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(mcast_intermediate_process, ev, data)
{
  static struct etimer energy_log_timer;

  PROCESS_BEGIN();

  PRINTF("Multicast Engine: '%s'\n", UIP_MCAST6.name);

  etimer_set(&energy_log_timer, ENERGY_LOG_DELAY * CLOCK_SECOND);

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
  }


  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
