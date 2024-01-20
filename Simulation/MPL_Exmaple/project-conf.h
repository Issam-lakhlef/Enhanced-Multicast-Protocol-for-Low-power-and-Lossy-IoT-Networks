#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

#include "net/ipv6/multicast/uip-mcast6-engines.h"

/* Change this to switch engines. Engine codes in uip-mcast6-engines.h */
#define UIP_MCAST6_CONF_ENGINE UIP_MCAST6_ENGINE_MPL // MCAST6_ENGINE


/* For Imin: Use 16 over NullRDC, 64 over Contiki MAC */
#define ROLL_TM_CONF_IMIN_1         64
#define MPL_CONF_DATA_MESSAGE_IMIN  64
#define MPL_CONF_DATA_MESSAGE_IMAX  0
#define MPL_CONF_CONTROL_MESSAGE_IMIN 64
#define MPL_CONF_BUFFERED_MESSAGE_SET_SIZE 6

#undef UIP_CONF_IPV6_RPL
#undef UIP_CONF_ND6_SEND_RA
#undef UIP_CONF_ROUTER
#define UIP_CONF_ND6_SEND_RA         0
#define UIP_CONF_ROUTER              1
#define UIP_MCAST6_ROUTE_CONF_ROUTES 1

#undef UIP_CONF_TCP
#define UIP_CONF_TCP 0

#define NETSTACK_CONF_RDC cxmac_driver
#define WITH_STROBE_BROADCAST 1
#define NETSTACK_CONF_MAC csma_driver
#define CSMA_CONF_MAX_FRAME_RETRIES 0

#define MPL_CONF_REACTIVE_FORWARDING 1 //reactive forwarding
#define MPL_CONF_PROACTIVE_FORWARDING 1 //proactive forwarding

/* Code/RAM footprint savings so that things will fit on our device */
#undef NBR_TABLE_CONF_MAX_NEIGHBORS
#undef UIP_CONF_MAX_ROUTES
#define NBR_TABLE_CONF_MAX_NEIGHBORS  10
#define UIP_CONF_MAX_ROUTES           10

#endif /* PROJECT_CONF_H_ */
