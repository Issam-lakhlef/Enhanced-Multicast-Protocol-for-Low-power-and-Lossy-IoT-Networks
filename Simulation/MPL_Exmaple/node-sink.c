#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/ipv6/multicast/uip-mcast6.h"
#include "sys/node-id.h"

#include <string.h>

#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

#include "sys/energest.h"

#define ENERGY_LOG_DELAY 295

#define MCAST_SINK_UDP_PORT 3001

static struct uip_udp_conn *sink_conn;
static uint16_t count;

uip_ipaddr_t addr;
uip_ds6_maddr_t *rv;

#define UIP_IP_BUF ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])

#if !NETSTACK_CONF_WITH_IPV6 || !UIP_CONF_ROUTER || !UIP_IPV6_MULTICAST || !UIP_CONF_IPV6_RPL
#error "1"
#endif
/*---------------------------------------------------------------------------*/
PROCESS(mcast_sink_process, "Multicast Sink");
AUTOSTART_PROCESSES(&mcast_sink_process);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(mcast_sink_process, ev, data)
{
  static struct etimer energy_log_timer;

  PROCESS_BEGIN();

  PRINTF("Multicast Engine: '%s'\n", UIP_MCAST6.name);

#if UIP_MCAST6_CONF_ENGINE != UIP_MCAST6_ENGINE_MPL
  uip_ip6addr(&addr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0, 0, 0, 0);
  uip_ds6_set_addr_iid(&addr, &uip_lladdr);
  uip_ds6_addr_add(&addr, 0, ADDR_AUTOCONF);

  uip_ip6addr(&addr, 0xFF1E, 0, 0, 0, 0, 0, 0x89, 0xABCD);
  rv = uip_ds6_maddr_add(&addr);

  if (rv == NULL)
  {
    PROCESS_EXIT();
  }
  #endif

  sink_conn = udp_new(NULL, UIP_HTONS(0), NULL);
  udp_bind(sink_conn, UIP_HTONS(MCAST_SINK_UDP_PORT));

  count = 0;

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

    if (ev == tcpip_event)
    {
      if (uip_newdata())
      {
        count++;
        PRINTF("In: [0x%08lx], TTL %u, total %u\n",
               uip_ntohl((unsigned long)*((uint32_t *)(uip_appdata))),
               UIP_IP_BUF->ttl, count);
      }
    }
    
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
