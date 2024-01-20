#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/ip/uip.h"
#include "net/ipv6/uip-ds6.h"
#include "net/ipv6/uip-icmp6.h"
#include "net/ipv6/multicast/uip-mcast6.h"
#include "net/ipv6/multicast/mpl.h"
#include "core/dev/watchdog.h"
#include "core/lib/trickle-timer.h"
#include "core/lib/list.h"
#include "sys/ctimer.h"
#include <string.h>
#include "lib/random.h"

#define DEBUG 0
#include "net/ip/uip-debug.h"

/*---------------------------------------------------------------------------*/
/* Check Parameters are Correct */
/*---------------------------------------------------------------------------*/
/* MPL Seed IDs */
#if MPL_SEED_ID_TYPE < 0 || MPL_SEED_ID_TYPE > 3
#error Invalid value for MPL_SEED_ID_TYPE
#endif
#if MPL_SEED_ID_TYPE == 0 && (MPL_SEED_ID_H > 0x00 || MPL_SEED_ID_L > 0x00)
#warning MPL Seed ID Set but not used due to Seed ID type setting
#endif
#if MPL_SEED_ID_TYPE == 1 && MPL_SEED_ID_H > 0x00
#warning MPL Seed ID upper 64 bits set but not used due to Seed ID type setting
#endif
#if MPL_SEED_ID_TYPE == 1 && MPL_SEED_ID_L > 0xFFFF
#error MPL Seed ID too large for Seed ID type setting
#endif
#if MPL_SEED_ID_TYPE == 2 && MPL_SEED_ID_H > 0x00
#warning MPL Seed ID upper 64 bits set yet not used due to Seed ID type setting
#endif
/*---------------------------------------------------------------------------*/
/* Data Representation */
/*---------------------------------------------------------------------------*/
/* MPL Seed IDs */
typedef struct seed_id_s {
  uint8_t s;
  uint8_t id[16];
} seed_id_t;
#define MPL_SEED_ID_UNKNOWN 0xFF
/* Define a way of logging the seed id /
/**************************************************/
#define LOG_SEED(seed_id) do { \
      PRINTF("[MPL]:0x%.2hx%.2hx%.2hx%.2hx%.2hx%.2hx%.2hx%.2hx%.2hx%.2hx%.2hx%.2hx%.2hx%.2hx%.2hx%.2hx", \
                 seed_id.id[15], seed_id.id[14], seed_id.id[13], seed_id.id[12], \
                 seed_id.id[11], seed_id.id[10], seed_id.id[9], seed_id.id[8], \
                 seed_id.id[7], seed_id.id[6], seed_id.id[5], seed_id.id[4], \
                 seed_id.id[3], seed_id.id[2], seed_id.id[1], seed_id.id[0]); \
} while(0);
/* Macros to //PRINT seed id in logs */
/****************************************/
#define LOG_INFO_SEED(...) LOG_SEED(__VA_ARGS__)

/* MPL Seed IDs can be either 16 bits, 64 bits, or 128 bits. If they are 128
 *  bits then the IPV6 Source address may also be used as the seed ID.
 *  These are always represented in contiki as a 128 bit number in the type
 *  seed_id_t. The functions below convert a seed id of various lengths to
 *  this 128 bit representation.
 */
/**
 * \brief Set the seed id to a 16 bit constant
 * dst: seed_id_t to set to the constant
 * src: 16 bit integer to set
 */
#define SEED_ID_S1(dst, src) { (*(uint16_t *)&(dst)->id) = (src); (dst)->s = 1; }
/**
 * \brief Set the seed id to a 64 bit constant
 * dst: seed_id_t to set to the constant
 * src: 64 bit integer to set
 */
#define SEED_ID_S2(dst, src) { (*(uint64_t *)&(dst)->id) = (src); (dst)->s = 2; }
/**
 * \brief Set the seed id to a 128 bit constant
 * dst: seed_id_t to set to the constant
 * l: Lower 64 bits of the seed id to set
 * h: Upper 64 bits of the seed id to set
 */
#define SEED_ID_S3(dst, l, h) { (*(uint64_t *)&(dst)->id) = (l); (*(uint64_t *)&(dst)->id[8]) = (h); (dst)->s = 3; }
/**
 * \brief Compare two contiki seed ids represented as seed_id_t types
 * a: First value to compare
 * b: Second value to compare
 */
#define seed_id_cmp(a, b) (memcmp((a)->id, (b)->id, sizeof(uint8_t) * 16) == 0)
/**
 * \brief Copy one seed_id_t into another.
 * a: Destination
 * b: Source
 */
#define seed_id_cpy(a, b) (memcpy((a), (b), sizeof(seed_id_t)))
/**
 * \brief Clear a seed id value to zero
 * a: Value to clear
 */
#define seed_id_clr(a) (memset((a), 0, sizeof(seed_id_t)))
/*---------------------------------------------------------------------------*/
/* Buffered message set
 *  This is implemented as a linked list since the majority of operations
 *  involve finding the minimum sequence number and iterating up the list.
 */
struct mpl_msg {
  struct mpl_msg *next; /* Next message in the set, or NULL if this is largest */
  struct mpl_seed *seed; /* The seed set this message belongs to */
  struct trickle_timer tt; /* The trickle timer associated with this msg */
  uip_ip6addr_t srcipaddr; /* The original ip this message was sent from */
  uint16_t size; /* Side of the data stored above */
  uint8_t seq; /* The sequence number of the message */
  uint8_t e; /* Expiration count for trickle timer */
  uint8_t data[UIP_BUFSIZE- UIP_LLH_LEN]; /* Message payload */
};
/**
 * \brief Get the state of the used flag in the buffered message set entry
 * h: pointer to the message set entry
 */
#define MSG_SET_IS_USED(h) ((h)->seed != NULL)
/**
 * \brief Clear the state of the used flag in the buffered message set entry
 * h: pointer to the message set entry
 */
#define MSG_SET_CLEAR_USED(h) ((h)->seed = NULL)
/* RFC 1982 Serial Number Arithmetic */
/**
 * \brief s1 is said to be equal s2 if SEQ_VAL_IS_EQ(s1, s2) == 1
 */
#define SEQ_VAL_IS_EQ(i1, i2) ((i1) == (i2))

/**
 * \brief s1 is said to be less than s2 if SEQ_VAL_IS_LT(s1, s2) == 1
 */
#define SEQ_VAL_IS_LT(i1, i2) \
  ( \
    ((i1) != (i2)) && \
    ((((i1) < (i2)) && ((int16_t)((i2) - (i1)) < 0x100)) || \
     (((i1) > (i2)) && ((int16_t)((i1) - (i2)) > 0x100))) \
  )

/**
 * \brief s1 is said to be greater than s2 iif SEQ_VAL_IS_LT(s1, s2) == 1
 */
#define SEQ_VAL_IS_GT(i1, i2) \
  ( \
    ((i1) != (i2)) && \
    ((((i1) < (i2)) && ((int16_t)((i2) - (i1)) > 0x100)) || \
     (((i1) > (i2)) && ((int16_t)((i1) - (i2)) < 0x100))) \
  )

/**
 * \brief Add n to s: (s + n) modulo (2 ^ SERIAL_BITS) => ((s + n) % 0x8000)
 */
#define SEQ_VAL_ADD(s, n) (((s) + (n)) % 0x100)
/*---------------------------------------------------------------------------*/

/* Seed Set */
struct mpl_seed {
  seed_id_t seed_id;
  uint8_t min_seqno; /* Used when the seed set is empty */
  uint8_t lifetime; /* Decrements by one every minute */
  uint8_t count; /* Only used for determining largest msg set during reclaim */
  LIST_STRUCT(min_seq); /* Pointer to the first msg in this seed's set */
  struct mpl_domain *domain; /* The domain this seed belongs to */
};
static void buffer_free(struct mpl_msg *msg); 

/**
 * \brief Get the state of the used flag in the buffered message set entry
 * h: pointer to the message set entry
 */
#define SEED_SET_IS_USED(h) (((h)->domain != NULL))
/**
 * \brief Clear the state of the used flag in the buffered message set entry
 * h: pointer to the message set entry
 */
#define SEED_SET_CLEAR_USED(h) ((h)->domain = NULL)
/*---------------------------------------------------------------------------*/
/* Domain Set */
struct mpl_domain {
  uip_ip6addr_t data_addr; /* Data address for this MPL domain */
  uip_ip6addr_t ctrl_addr; /* Link-local scoped version of data address */
  struct trickle_timer tt;
  uint8_t e; /* Expiration count for trickle timer */
};
/**
 * \brief Get the state of the used flag in the buffered message set entry
 * h: pointer to the message set entry
 */
#define DOMAIN_SET_IS_USED(h) (uip_is_addr_mcast(&(h)->data_addr))
/**
 * \brief Clear the state of the used flag in the buffered message set entry
 * h: pointer to the message set entry
 */
#define DOMAIN_SET_CLEAR_USED(h) (memset(&(h)->data_addr, 0, sizeof(uip_ip6addr_t)))
/*---------------------------------------------------------------------------*/
/**
 * Hop-by-Hop Options Header
 * The header can take different forms depending on the length of the seed id,
 * so all the different representations are shown here.
 */
struct mpl_hbho {
  uint8_t type;
  uint8_t len;
  uint8_t flags;
  uint8_t seq;
  struct uip_ext_hdr_opt_padn padn;
};
struct mpl_hbho_s1 {
  uint8_t type;
  uint8_t len;
  uint8_t flags;
  uint8_t seq;
  uint16_t seed_id;
};
struct mpl_hbho_s2 {
  uint8_t type;
  uint8_t len;
  uint8_t flags;
  uint8_t seq;
  uint64_t seed_id;
  struct uip_ext_hdr_opt_padn padn;
};
struct mpl_hbho_s3 {
  uint8_t type;
  uint8_t len;
  uint8_t flags;
  uint8_t seq;
  uint8_t seed_id[16];
  struct uip_ext_hdr_opt_padn padn;
};
/**
 * \brief Get the MPL Parametrization for a multicast HBHO header
 * m: pointer to the HBHO header
 */
#define HBH_GET_S(h) (((h)->flags & 0xC0) >> 6)

/**
 * \brief Set the MPL Parametrization bit for a multicast HBHO header
 * m: pointer to the HBHO header
 */
#define HBH_SET_S(h, s) ((h)->flags |= ((s & 0x03) << 6))

/**
 * \brief Clear the MPL Parametrization bit for a multicast HBHO header
 * m: pointer to the HBHO header
 */
#define HBH_CLR_S(h) ((h)->flags &= ~0xC0)

/**
 * \brief Get the MPL Parametrization for a multicast HBHO header
 * m: pointer to the HBHO header
 */
#define HBH_GET_M(h) (((h)->flags & 0x20) == 0x20)

/**
 * \brief Set the MPL Parametrization bit for a multicast HBHO header
 * m: pointer to the HBHO header
 */
#define HBH_SET_M(h) ((h)->flags |= 0x20)

/**
 * \brief Get the MPL Parametrization for a multicast HBHO header
 * m: pointer to the HBHO header
 */
#define HBH_GET_V(h) (((h)->flags & 0x10) == 0x10)

/**
 * \brief Set the MPL Parametrization bit for a multicast HBHO header
 * m: pointer to the HBHO header
 */
#define HBH_CLR_V(h) ((h)->flags &= ~0x10)
/* Outdoing msg HBHO Sizes */
#if MPL_SEED_ID_TYPE == 0
#define HBHO_TOTAL_LEN HBHO_BASE_LEN + HBHO_S0_LEN
#elif MPL_SEED_ID_TYPE == 1
#define HBHO_TOTAL_LEN HBHO_BASE_LEN + HBHO_S1_LEN
#elif MPL_SEED_ID_TYPE == 2
#define HBHO_TOTAL_LEN HBHO_BASE_LEN + HBHO_S2_LEN
#elif MPL_SEED_ID_TYPE == 3
#define HBHO_TOTAL_LEN HBHO_BASE_LEN + HBHO_S3_LEN
#endif
/*---------------------------------------------------------------------------*/
#if MPL_REACTIVE_FORWARDING
/** Seed Info Payload
 * This is the payload sent in ICMP Control messages. It changes based on the
 * Seed ID length being sent, so all the different representations it can take
 * are shown here.
 */
struct seed_info {
  uint8_t min_seqno;
  uint8_t bm_len_S; /* First 6 bits bm-len, last 2 S */
};
struct seed_info_s1 {
  uint8_t min_seqno;
  uint8_t bm_len_S; /* First 6 bits bm-len, last 2 S */
  uint16_t seed_id;
};
struct seed_info_s2 {
  uint8_t min_seqno;
  uint8_t bm_len_S; /* First 6 bits bm-len, last 2 S */
  uint64_t seed_id;
};
struct seed_info_s3 {
  uint8_t min_seqno;
  uint8_t bm_len_S; /* First 6 bits bm-len, last 2 S */
  uint8_t seed_id[16];
};
#endif

/**
 * \brief Get the S bits in the length/S field in the seed info header
 * h: pointer to the seed info struct
 */
#define SEED_INFO_GET_S(h) ((h)->bm_len_S & 0x03)
/**
 * \brief Clear the S bits within the length/S field in the seed info header
 * h: pointer to the seed info struct
 */
#define SEED_INFO_CLR_S(h) ((h)->bm_len_S &= ~0x03)
/**
 * \brief Set the S bits within the seed info struct. These must be cleared beforehand.
 * h: Pointer to the seed info struct
 * s: value (0-3) that the S bits should be set to
 */
#define SEED_INFO_SET_S(h, s) ((h)->bm_len_S |= (s & 0x03))
/**
 * \brief Get the length bits from the seed info struct.
 * h: pointer to seed info struct.
 */
#define SEED_INFO_GET_LEN(h) ((h)->bm_len_S >> 2)
/**
 * \brief Clear the length bits in the seed info struct.
 * h: pointer to the seed info struct
 */
#define SEED_INFO_CLR_LEN(h) ((h)->bm_len_S &= 0x03)
/**
 * \brief Set the length bits in the seed info struct. These must be cleared beforehand.
 * h: pointer to the seed info struct
 * l: Length value (0-63) that the length bits should be set to
 */
#define SEED_INFO_SET_LEN(h, l) ((h)->bm_len_S |= (l << 2))
/*---------------------------------------------------------------------------*/
/* Maintain Stats */
/*---------------------------------------------------------------------------*/
#if UIP_MCAST6_STATS
static struct mpl_stats stats;

#define MPL_STATS_ADD(x) stats.x++
#define MPL_STATS_INIT() do { memset(&stats, 0, sizeof(stats)); } while(0)
#else /* UIP_MCAST6_STATS */
#define MPL_STATS_ADD(x)
#define MPL_STATS_INIT()
#endif
/*---------------------------------------------------------------------------*/
/* Internal Data Structures */
/*---------------------------------------------------------------------------*/
static struct mpl_msg buffered_message_set[MPL_BUFFERED_MESSAGE_SET_SIZE];
static struct mpl_seed seed_set[MPL_SEED_SET_SIZE];
static struct mpl_domain domain_set[MPL_DOMAIN_SET_SIZE];
static uint16_t last_seq;
static seed_id_t local_seed_id;
#if MPL_SUB_TO_ALL_FORWARDERS
static uip_ip6addr_t all_forwarders;
#endif
static struct ctimer lifetime_timer;
/*---------------------------------------------------------------------------*/
/* Temporary Stores */
/*---------------------------------------------------------------------------*/
static struct mpl_hbho *lochbhmptr;  /* HBH Header Pointer */
static struct mpl_seed *locssptr;  /* Seed Set Pointer */
static struct mpl_msg *locmmptr;  /* MPL Message Pointer */
static struct mpl_domain *locdsptr;  /* Domain set pointer */
static struct seed_info *locsiptr;  /* Seed Info Pointer */
/*---------------------------------------------------------------------------*/
/* uIPv6 Pointers */
/*---------------------------------------------------------------------------*/

#define UIP_DATA_BUF      ((uint8_t *)&uip_buf[uip_l2_l3_hdr_len + UIP_UDPH_LEN])
#define UIP_UDP_BUF       ((struct uip_udp_hdr *)&uip_buf[uip_l2_l3_hdr_len])
#define UIP_EXT_BUF       ((struct uip_ext_hdr *)&uip_buf[UIP_LLH_LEN + UIP_IPH_LEN])
#define UIP_EXT_BUF_NEXT  ((uint8_t *)&uip_buf[UIP_LLH_LEN + UIP_IPH_LEN + HBHO_TOTAL_LEN])
#define UIP_EXT_OPT_FIRST ((struct mpl_hbho *)&uip_buf[UIP_LLH_LEN + UIP_IPH_LEN + 2])
#define UIP_IP_BUF        ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_ICMP_BUF      ((struct uip_icmp_hdr *)&uip_buf[uip_l2_l3_hdr_len])
#define UIP_ICMP_PAYLOAD  ((unsigned char *)&uip_buf[uip_l2_l3_icmp_hdr_len])

extern uint16_t uip_slen;


/*---------------------------------------------------------------------------*/
/* Local Macros */
/*---------------------------------------------------------------------------*/
/**
 * \brief Start the trickle timer for a control message
 * t: Pointer to set that should be reset
 */
#if MPL_REACTIVE_FORWARDING
#define mpl_control_trickle_timer_start(t) { (t)->e = 0; trickle_timer_set(&(t)->tt, control_message_expiration, (t)); }
#endif
/**
 * \brief Start the trickle timer for a data message
 * t: Pointer to set that should be reset
 */
#define mpl_data_trickle_timer_start(t) { (t)->e = 0; trickle_timer_set(&(t)->tt, data_message_expiration, (t)); }
#define mpl_data_trickle_timer_start_rea(t) { (t)->e = 0; trickle_timer_set(&(t)->tt, data_message_expiration_rea, (t)); } // enhanced REA in Hybrid mode DATA_MESSAGE_EXPRATION == 1
/**
 * \brief Call inconsistency on the provided timer
 * t: Pointer to set that should be reset
 */
#define mpl_trickle_timer_inconsistency(t) { (t)->e = 0; trickle_timer_inconsistency(&(t)->tt); }
/**
 * \brief Reset the trickle timer and expiration count for the set
 * t: Pointer to set that should be reset
 */
#define mpl_trickle_timer_reset(t) { (t)->e = 0; trickle_timer_reset_event(&(t)->tt); }
/**
 * \brief Set a single bit within a bit vector that spans multiple bytes
 * v: The bit vector
 * b: The 0-indexed bit to set
 */
#define BIT_VECTOR_SET_BIT(v, b) (v[b / 8] |= (0x80 >> b % 8))
/**
 * \brief Get the value of a bit in a bit vector
 * v: The bit vector
 * b: The 0-indexed bit to get
 */
#define BIT_VECTOR_GET_BIT(v, b) ((v[b / 8] & (0x80 >> b % 8)) == (0x80 >> b % 8))
/** 10000000
 * \brief Modify an ipv6 address to give it link local scope
 * a: uip_ip6addr_t address to modify
 */
#define UIP_ADDR_MAKE_LINK_LOCAL(a) (((uip_ip6addr_t *)a)->u8[1] = UIP_MCAST6_SCOPE_LINK_LOCAL)
/*---------------------------------------------------------------------------*/
/* Local function prototypes */
/*---------------------------------------------------------------------------*/
#if MPL_REACTIVE_FORWARDING
static void icmp_in(void);
UIP_ICMP6_HANDLER(mpl_icmp_handler, ICMP6_MPL, 0, icmp_in);
#endif
static struct mpl_msg *
buffer_allocate(void)
{
  for(locmmptr = &buffered_message_set[MPL_BUFFERED_MESSAGE_SET_SIZE - 1]; locmmptr >= buffered_message_set; locmmptr--) {
    if(!MSG_SET_IS_USED(locmmptr)) {
      memset(locmmptr, 0, sizeof(struct mpl_msg));
      return locmmptr;
    }
  }
  return NULL;
}
static void
buffer_free(struct mpl_msg *msg)
{
  if(trickle_timer_is_running(&msg->tt)) {
    trickle_timer_stop(&msg->tt);
  }
  MSG_SET_CLEAR_USED(msg);
}
static struct mpl_msg *
buffer_reclaim(void)
{
  static struct mpl_seed *ssptr; /* Can't use locssptr since it's used by calling function */
  static struct mpl_seed *largest;
  static struct mpl_msg *reclaim;

  /* Reclaim the message with min_seq in the largest seed set */
  largest = NULL;
  reclaim = NULL;
  for(ssptr = &seed_set[MPL_SEED_SET_SIZE]; ssptr >= seed_set; ssptr--) {
    if(SEED_SET_IS_USED(ssptr) && (largest == NULL || ssptr->count > largest->count)) {
      largest = ssptr;
    }
  }
  /**
   * To reclaim this, we need to increment the min seq number to
   *   the next largest sequence number in the set.
   * This won't necessarily be min_seq + 1 because MPL does not require or
   *   ensure that sequence number are sequential, it just denotes the
   *   order messages are sent.
   * We've already worked out what this new value is.
   */
  if(largest != NULL) {
    reclaim = list_pop(largest->min_seq);
    largest->min_seqno = list_item_next(reclaim) == NULL ? reclaim->seq : ((struct mpl_msg *)list_item_next(reclaim))->seq;
    largest->count--;
    trickle_timer_stop(&reclaim->tt);
    mpl_trickle_timer_reset(reclaim->seed->domain);
    memset(reclaim, 0, sizeof(struct mpl_msg));
  }
  return reclaim;
}
static struct mpl_domain *
domain_set_allocate(uip_ip6addr_t *address)
{
  uip_ip6addr_t data_addr;
  uip_ip6addr_t ctrl_addr;
  /* Determine the two addresses for this domain */
  if(uip_mcast6_get_address_scope(address) == UIP_MCAST6_SCOPE_LINK_LOCAL) {
    PRINTF("[MPL]:Domain Set Allocate has a local scoped address\n");
    memcpy(&data_addr, address, sizeof(uip_ip6addr_t));
    memcpy(&ctrl_addr, address, sizeof(uip_ip6addr_t));
    do {
      data_addr.u8[1]++;
      if(uip_ds6_maddr_lookup(&data_addr)) {
        PRINTF("[MPL]:Found higher scoped address in table\n");
        break;
      }
    } while(data_addr.u8[1] <= 5);
    if(data_addr.u8[1] > 5) {
      PRINTF("[MPL]:Failed to find MPL domain data address in table\n");
      return NULL;
    }
  } else {
    memcpy(&data_addr, address, sizeof(uip_ip6addr_t));
    memcpy(&ctrl_addr, address, sizeof(uip_ip6addr_t));
    UIP_ADDR_MAKE_LINK_LOCAL(&ctrl_addr);
  }
  /* Now try the allocation */
  for(locdsptr = &domain_set[MPL_DOMAIN_SET_SIZE - 1]; locdsptr >= domain_set; locdsptr--) {
    if(!DOMAIN_SET_IS_USED(locdsptr)) {
      if(!uip_ds6_maddr_lookup(&ctrl_addr) && !uip_ds6_maddr_add(&ctrl_addr)) {
        PRINTF("[MPL]:Failed to subscribe to link local address for domain ");
        PRINT6ADDR(address);
        PRINTF("\n");
        return NULL;
      }
      memset(locdsptr, 0, sizeof(struct mpl_domain));
      memcpy(&locdsptr->data_addr, &data_addr, sizeof(uip_ip6addr_t));
      memcpy(&locdsptr->ctrl_addr, &ctrl_addr, sizeof(uip_ip6addr_t));
#if MPL_REACTIVE_FORWARDING
      if(!trickle_timer_config(&locdsptr->tt,
                               MPL_CONTROL_MESSAGE_IMIN,
                               MPL_CONTROL_MESSAGE_IMAX,
                               MPL_CONTROL_MESSAGE_K)) {
        PRINTF("[MPL]:Unable to configure trickle timer for domain. Dropping,...\n");
        DOMAIN_SET_CLEAR_USED(locdsptr);
        return NULL;
      }
#endif
      return locdsptr;
    }
  }
  return NULL;
}
/* Lookup the seed id in the seed set */
static struct mpl_seed *
seed_set_lookup(seed_id_t *seed_id, struct mpl_domain *domain)
{
  for(locssptr = &seed_set[MPL_SEED_SET_SIZE - 1]; locssptr >= seed_set; locssptr--) {
    if(SEED_SET_IS_USED(locssptr) && seed_id_cmp(seed_id, &locssptr->seed_id) && locssptr->domain == domain) {
      return locssptr;
    }
  }
  return NULL;
}
static struct mpl_seed *
seed_set_allocate(void)
{ 
  for(locssptr = &seed_set[MPL_SEED_SET_SIZE - 1]; locssptr >= seed_set; locssptr--) {
    if(!SEED_SET_IS_USED(locssptr)) {
      locssptr->count = 0;
      LIST_STRUCT_INIT(locssptr, min_seq);
      uint8_t i;
      return locssptr;
    }
  }
  return NULL;
}
static void
seed_set_free(struct mpl_seed *s)
{
  while((locmmptr = list_pop(s->min_seq)) != NULL) {
    buffer_free(locmmptr);
  }
  SEED_SET_CLEAR_USED(s);
}
static struct mpl_domain *
domain_set_lookup(uip_ip6addr_t *domain)
{
  for(locdsptr = &domain_set[MPL_DOMAIN_SET_SIZE - 1]; locdsptr >= domain_set; locdsptr--) {
    if(DOMAIN_SET_IS_USED(locdsptr)) {
      if(uip_ip6addr_cmp(domain, &locdsptr->data_addr)
         || uip_ip6addr_cmp(domain, &locdsptr->ctrl_addr)) {
        return locdsptr;
      }
    }
  }
  return NULL;
}
static void
domain_set_free(struct mpl_domain *domain)
{
  uip_ds6_maddr_t *addr;
  /* Must include freeing seeds otherwise we leak memory */
  for(locssptr = &seed_set[MPL_SEED_SET_SIZE]; locssptr >= seed_set; locssptr--) {
    if(SEED_SET_IS_USED(locssptr) && locssptr->domain == domain) {
      seed_set_free(locssptr);
    }
  }
  addr = uip_ds6_maddr_lookup(&domain->data_addr);
  if(addr != NULL) {
    uip_ds6_maddr_rm(addr);
  }
  addr = uip_ds6_maddr_lookup(&domain->ctrl_addr);
  if(addr != NULL) {
    uip_ds6_maddr_rm(addr);
  }
  if(trickle_timer_is_running(&domain->tt)) {
    trickle_timer_stop(&domain->tt);
  }
  DOMAIN_SET_CLEAR_USED(domain);
}
static void
seed_id_net_to_host(seed_id_t *dst, void *src, uint8_t s)
{
  /**
   * Convert a seed id in network order header format and length S to
   * internal representation.
   */
  static uint8_t i;
  static uint8_t *ptr;
  ptr = src;
  switch(s) {
  case 0:
    /* 128 bit seed ID from IPV6 Address */
    dst->s = 0;
    for(i = 0; i < 16; i++) {
      dst->id[i] = ptr[15 - i];
    }
    return;
  case 1:
    /* 16 bit seed ID */
    dst->s = 1;
    for(i = 2; i < 15; i++) {
      /* Clear the first 13 bytes in the id */
      dst->id[i] = 0;
    }
    dst->id[0] = ptr[1];
    dst->id[1] = ptr[0];
    return;
  case 2:
    /* 64 bit Seed ID */
    dst->s = 2;
    for(i = 0; i < 8; i++) {
      /* Reverse the byte order */
      dst->id[i] = ptr[7 - i];
    }
    for(i = 8; i < 16; i++) {
      /* Set the remainder to zero */
      dst->id[i] = 0;
    }
    return;
  case 3:
    /* 128 bit seed ID */
    dst->s = 3;
    for(i = 0; i < 16; i++) {
      dst->id[i] = ptr[15 - i];
    }
    return;
  default:
    /* Invalid seed size */
    return;
  }
}
static void
seed_id_host_to_net(void *dst, seed_id_t *src)
{
  /**
   * Convert a seed id from our internal representation to network
   * order and representation based on length s.
   */
  static uint8_t i;
  static uint8_t *ptr;
  ptr = dst;
  switch(src->s) {
  case 0:
  case 3:
    /* Both use 128 bit seed IDs and do exactly the same thing */
    for(i = 0; i < 16; i++) {
      /* Byte order must be swapped */
      ptr[i] = src->id[15 - i];
    }
    return;
  case 1:
    /* 16 bit seed id */
    ptr[0] = src->id[1];
    ptr[1] = src->id[0];
    return;
  case 2:
    /* 64 bit Seed ID */
    for(i = 0; i < 8; i++) {
      ptr[i] = src->id[7 - i];
    }
    return;
  default:
    /* Invalid seed size */
    return;
  }
}
static void
update_seed_id(void)
{
  /* Load my seed ID into memory */
#if MPL_SEED_ID_TYPE == 0
  /* Copy seed ID from out link local ip address */
  static uip_ds6_addr_t *my_ip6_addr;
  my_ip6_addr = uip_ds6_get_global(ADDR_PREFERRED);
  if(my_ip6_addr != NULL) {
    seed_id_net_to_host(&local_seed_id, &my_ip6_addr->ipaddr, 0);
  } else {
    local_seed_id.s = MPL_SEED_ID_UNKNOWN;
    PRINTF("[MPL]:Seed id not yet known.\n");
    return;
  }
#elif MPL_SEED_ID_TYPE == 1
  /* 16 bit seed id */
  SEED_ID_S1(&local_seed_id, MPL_SEED_ID_L);
#elif MPL_SEED_ID_TYPE == 2
  /* 64 bit seed id */
  SEED_ID_S2(&local_seed_id, MPL_SEED_ID_L);
#elif MPL_SEED_ID_TYPE == 3
  /* 128 bit seed id */
  SEED_ID_S3(&local_seed_id, MPL_SEED_ID_L, MPL_SEED_ID_H);
#endif

  PRINTF("[MPL]:My seed id is ");
  LOG_INFO_SEED(local_seed_id);
  PRINTF("[MPL]: with S=%u\n", local_seed_id.s);
}

/*TrickleMAC*/ // we use these variables to designate the message that is not sent either data or control.  
uint8_t unsend = 0;
uint8_t icmp_unsend = 0;
uint8_t data_traitement = 0;
uint8_t icmp_traitement = 0;
void unsend_MPL_Trickle_m(void){
 if(data_traitement==1) {
  unsend = 1;
 }else{
   if(icmp_traitement == 1){icmp_unsend = 1;}   
 }
 return;
} 
/*-----------*/

#if MPL_REACTIVE_FORWARDING
void
icmp_out(struct mpl_domain *dom)
{
  icmp_traitement = 1; // start ICMP message sending process

  uint8_t vector[32];
  uint8_t vec_size;
  uint8_t vec_len;
  uint8_t cur_seq;
  uint16_t payload_len;
  uip_ds6_addr_t *addr;
  size_t seed_info_len;

  UIP_IP_BUF->vtc = 0x60; //96
  UIP_IP_BUF->tcflow = 0;
  UIP_IP_BUF->flow = 0;
  UIP_IP_BUF->proto = UIP_PROTO_ICMP6;
  UIP_IP_BUF->ttl = MPL_IP_HOP_LIMIT;

  locsiptr = (struct seed_info *)UIP_ICMP_PAYLOAD;
  payload_len = 0;

  /* Set the source address to link local for now. If we need to, we can try changing it to global later */
  uip_ip6addr_copy(&UIP_IP_BUF->destipaddr, &dom->ctrl_addr);
  uip_ds6_select_src(&UIP_IP_BUF->srcipaddr, &UIP_IP_BUF->destipaddr);

  /* Iterate over seed set to create payload */
  for(locssptr = &seed_set[MPL_SEED_SET_SIZE - 1]; locssptr >= seed_set; locssptr--) {
    if(SEED_SET_IS_USED(locssptr) && locssptr->domain == dom) {
      locsiptr->min_seqno = locssptr->min_seqno;
      SEED_INFO_CLR_LEN(locsiptr);
      SEED_INFO_CLR_S(locsiptr);

      /* Try setting our source address to global */
      addr = uip_ds6_get_global(ADDR_PREFERRED);
      if(addr) {
        uip_ip6addr_copy(&UIP_IP_BUF->srcipaddr, &addr->ipaddr);
      } else {
        /* Failed setting a global ip address, fallback to link local */
        uip_ds6_select_src(&UIP_IP_BUF->srcipaddr, &UIP_IP_BUF->destipaddr);
        if(uip_is_addr_unspecified(&UIP_IP_BUF->srcipaddr)) {
          PRINTF("[MPL]:icmp out: Cannot set src ip\n");
          uip_clear_buf();
          return;
        }
      }

      /* Set the Seed ID */
      switch(locssptr->seed_id.s) {
      case 0:
        if(uip_ip6addr_cmp((uip_ip6addr_t *)&locssptr->seed_id.id, &UIP_IP_BUF->srcipaddr)) {
          /* We can use an S=0 Seed ID */
          SEED_INFO_SET_LEN(locsiptr, 0);
          break;
        } /* Else fall down into the S = 3 case */
      case 3:
        seed_id_host_to_net(&((struct seed_info_s3 *)locsiptr)->seed_id, &locssptr->seed_id);
        SEED_INFO_SET_S(locsiptr, 3);
        break;
      case 1:
        seed_id_host_to_net(&((struct seed_info_s1 *)locsiptr)->seed_id, &locssptr->seed_id);
        SEED_INFO_SET_S(locsiptr, 1);
        break;
      case 2:
        seed_id_host_to_net(&((struct seed_info_s2 *)locsiptr)->seed_id, &locssptr->seed_id);
        SEED_INFO_SET_S(locsiptr, 2);
        break;
      }

      /* Populate the seed info message vector */
      memset(vector, 0, sizeof(vector));

      vec_len = 0;
      cur_seq = 0;
      PRINTF("[MPL]:\nBuffer for seed: ");
      LOG_INFO_SEED(locssptr->seed_id);
      PRINTF("[MPL]:\n");
/**
  *list_head is a lib/list.c function return the head of the liste (locssptr->min_seq list in this cas)
  *list_item_next next element in the list
**/
      for(locmmptr = list_head(locssptr->min_seq); locmmptr != NULL; locmmptr = list_item_next(locmmptr)) {
        PRINTF("[MPL]:%d -- %x\n", locmmptr->seq, locmmptr->data[locmmptr->size - 1]);
        cur_seq = SEQ_VAL_ADD(locssptr->min_seqno, vec_len);
        if(locmmptr->seq == SEQ_VAL_ADD(locssptr->min_seqno, vec_len)) {
          BIT_VECTOR_SET_BIT(vector, vec_len);
          vec_len++;
        } else {
          /* Insert enough zeros to get to the next message */
          vec_len += locmmptr->seq - cur_seq;
          BIT_VECTOR_SET_BIT(vector, vec_len);
          vec_len++;
        }
      }
  
      /* Convert vector length from bits to bytes */
      vec_size = (vec_len - 1) / 8 + 1;

      SEED_INFO_SET_LEN(locsiptr, vec_size);

      PRINTF("[MPL]:--- Control Message Entry ---\n");
      PRINTF("[MPL]:Seed ID: ");
      LOG_INFO_SEED(locssptr->seed_id);
      PRINTF("[MPL]:\n");
      PRINTF("[MPL]:S=%u\n", locssptr->seed_id.s);
      PRINTF("[MPL]:Min Sequence Number: %u\n", locssptr->min_seqno);
      PRINTF("[MPL]:Size of message set: %u\n", vec_len);
      PRINTF("[MPL]:Vector is %u bytes\n", vec_size);

      /* Copy vector into payload and point ptr to next location */
      switch(SEED_INFO_GET_S(locsiptr)) {
      case 0:
        seed_info_len = sizeof(struct seed_info);
        break;
      case 1:
        seed_info_len = sizeof(struct seed_info_s1);
        break;
      case 2:
        seed_info_len = sizeof(struct seed_info_s2);
        break;
      case 3:
        seed_info_len = sizeof(struct seed_info_s3);
        break;
      }
      memcpy(((void *)locsiptr) + seed_info_len, vector, vec_size);
      locsiptr = ((void *)locsiptr) + seed_info_len + vec_size;
      payload_len += seed_info_len + vec_size;
    }
    /* Now go to next seed in set */
  }
  PRINTF("[MPL]:--- End of Messages --\n");

  /* Finish off construction of ICMP Packet */
  UIP_IP_BUF->len[0] = (UIP_ICMPH_LEN + payload_len) >> 8;
  UIP_IP_BUF->len[1] = (UIP_ICMPH_LEN + payload_len) & 0xff;

  UIP_ICMP_BUF->type = ICMP6_MPL;
  UIP_ICMP_BUF->icode = 0;
  uip_len = UIP_IPH_LEN + UIP_ICMPH_LEN + payload_len;
  UIP_ICMP_BUF->icmpchksum = 0;
  UIP_ICMP_BUF->icmpchksum = ~uip_icmp6chksum();

  PRINTF("[MPL]:ICMP Out from ");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF("[MPL]: to ");
  PRINT6ADDR(&UIP_IP_BUF->destipaddr);
  PRINTF("\n");

  PRINTF("[MPL]:MPL Contol Message Out - %u bytes\n", payload_len);
  tcpip_ipv6_output();

    if(icmp_unsend == 1)
    {
	icmp_unsend = 0;
        if(trickle_a(&dom->tt) > 0){ // must be < cts=0
		printf("ICMP trickle end a = %u \n",trickle_a(&dom->tt));
	  	resend(1, &dom->tt); 
                dom->e++;
            }else{
	      printf("[MPL]: icmp_unsend ICMP multicast packet\n");
        resend(0, &dom->tt);
	// program another sending
        }
    }else{
	resend(1, &dom->tt);
	printf("Multicast ICMPv6 packet sent !!\n");
	dom->e++;
        MPL_STATS_ADD(icmp_out);
    }
    uip_clear_buf();
  icmp_traitement = 0; // end of ICMP packet sending process
  return;
}
#endif

#if MPL_REACTIVE_FORWARDING
static void
control_message_expiration(void *ptr, uint8_t suppress)
{
  /* Control message timer callback */
  locdsptr = ((struct mpl_domain *)ptr);
  if(locdsptr->e > MPL_CONTROL_MESSAGE_TIMER_EXPIRATIONS) {
    /* Disable the trickle timer for now */
    trickle_timer_stop(&locdsptr->tt);
    return;
  }
  if(suppress == TRICKLE_TIMER_TX_OK) {
    /* Send an MPL Control Message */
    icmp_out(locdsptr);
  }else{
   printf("no icmp trasmit e = %u\n",locdsptr->e);
   resend(1, &locdsptr->tt);
  }
  locdsptr->e++;
}
#endif

static void
data_message_expiration(void *ptr, uint8_t suppress)
{ 
  data_traitement = 1; // start data packet sending process
  /* Callback for data message trickle timers */
  locmmptr = ((struct mpl_msg *)ptr);
  if(locmmptr->e > MPL_DATA_MESSAGE_TIMER_EXPIRATIONS) {
    /* Terminate the trickle timer here if we've already expired enough times */
    trickle_timer_stop(&locmmptr->tt);
  /* Start the control message timer after the proactive mechanism */


/**********************TrickleMAC Enhanced HYB MODE************************/
#if MPL_REACTIVE_FORWARDING

  locdsptr = domain_set_lookup(&locmmptr->seed->domain->data_addr);
  printf("Lancer le traitement reactif apret proactive traitement\n");
#if MPL_CONTROL_MESSAGE_TIMER_EXPIRATIONS > 0
  if(!trickle_timer_is_running(&locdsptr->tt)) {
    mpl_control_trickle_timer_start(locdsptr);
  } else {
    mpl_trickle_timer_reset(locdsptr);
  }
#endif
#endif
    return;
  }

  if(suppress == TRICKLE_TIMER_TX_OK) { /* Only transmit if not suppressed */
    PRINTF("[MPL]:Data message TX\n");
    PRINTF("[MPL]:Seed ID=");
    LOG_INFO_SEED(locmmptr->seed->seed_id);
    PRINTF("[MPL]:, S=%u, Seq=%u\n", locmmptr->seed->seed_id.s, locmmptr->seq);
    /* Setup the IP Header */
    UIP_IP_BUF->vtc = 0x60;
    UIP_IP_BUF->tcflow = 0;
    UIP_IP_BUF->flow = 0;
    UIP_IP_BUF->proto = UIP_PROTO_HBHO;
    /*UIP_IP_BUF->ttl = MPL_IP_HOP_LIMIT; */
    uip_ip6addr_copy(&UIP_IP_BUF->destipaddr, &locmmptr->seed->domain->data_addr);
    uip_len = UIP_IPH_LEN;
    /* Setup the HBHO Header */
    UIP_EXT_BUF->next = UIP_PROTO_UDP;
    lochbhmptr = UIP_EXT_OPT_FIRST;
    lochbhmptr->type = HBHO_OPT_TYPE_MPL;
    lochbhmptr->flags = 0x00;
    switch(locmmptr->seed->seed_id.s) {
    case 0:
      UIP_EXT_BUF->len = HBHO_S0_LEN / 8;
      lochbhmptr->len = MPL_OPT_LEN_S0;
      HBH_CLR_S(lochbhmptr);
      HBH_SET_S(lochbhmptr, 0);
      uip_len += HBHO_BASE_LEN + HBHO_S0_LEN;
      uip_ext_len += HBHO_BASE_LEN + HBHO_S0_LEN;
      lochbhmptr->padn.opt_type = UIP_EXT_HDR_OPT_PADN;
      lochbhmptr->padn.opt_len = 0x00;
      break;
    case 1:
      UIP_EXT_BUF->len = HBHO_S1_LEN / 8;
      lochbhmptr->len = MPL_OPT_LEN_S1;
      HBH_CLR_S(lochbhmptr);
      HBH_SET_S(lochbhmptr, 1);
      seed_id_host_to_net(&((struct mpl_hbho_s1 *)lochbhmptr)->seed_id, &locmmptr->seed->seed_id);
      uip_len += HBHO_BASE_LEN + HBHO_S1_LEN;
      uip_ext_len += HBHO_BASE_LEN + HBHO_S1_LEN;
      break;
    case 2:
      UIP_EXT_BUF->len = HBHO_S2_LEN / 8;
      lochbhmptr->len = MPL_OPT_LEN_S2;
      HBH_CLR_S(lochbhmptr);
      HBH_SET_S(lochbhmptr, 2);
      seed_id_host_to_net(&((struct mpl_hbho_s2 *)lochbhmptr)->seed_id, &locmmptr->seed->seed_id);
      uip_len += HBHO_BASE_LEN + HBHO_S2_LEN;
      uip_ext_len += HBHO_BASE_LEN + HBHO_S2_LEN;
      ((struct mpl_hbho_s2 *)lochbhmptr)->padn.opt_type = UIP_EXT_HDR_OPT_PADN;
      ((struct mpl_hbho_s2 *)lochbhmptr)->padn.opt_len = 0x00;
      break;
    case 3:
      UIP_EXT_BUF->len = HBHO_S3_LEN / 8;
      lochbhmptr->len = MPL_OPT_LEN_S3;
      HBH_CLR_S(lochbhmptr);
      HBH_SET_S(lochbhmptr, 3);
      seed_id_host_to_net(&((struct mpl_hbho_s3 *)lochbhmptr)->seed_id, &locmmptr->seed->seed_id);
      uip_len += HBHO_BASE_LEN + HBHO_S3_LEN;
      uip_ext_len += HBHO_BASE_LEN + HBHO_S3_LEN;
      ((struct mpl_hbho_s3 *)lochbhmptr)->padn.opt_type = UIP_EXT_HDR_OPT_PADN;
      ((struct mpl_hbho_s3 *)lochbhmptr)->padn.opt_len = 0x00;
      break;
    }
    lochbhmptr->seq = locmmptr->seq;
    if(list_item_next(locmmptr) == NULL) {
      HBH_SET_M(lochbhmptr);
    }
    /* Now insert payload */
    memcpy(((void *)UIP_EXT_BUF) + 8 + UIP_EXT_BUF->len * 8, &locmmptr->data, locmmptr->size);
    uip_len += locmmptr->size;

    UIP_IP_BUF->len[0] = ((uip_len - UIP_IPH_LEN) >> 8);
    UIP_IP_BUF->len[1] = ((uip_len - UIP_IPH_LEN) & 0xff);

    uip_ip6addr_copy(&UIP_IP_BUF->srcipaddr, &locmmptr->srcipaddr);
    tcpip_output(NULL);

    if(unsend == 1)
    {   unsend = 0;
        if(trickle_a(&locmmptr->tt) > 0){
		printf("trickle end a = %u \n",trickle_a(&locmmptr->tt));
	  	resend(1, &locmmptr->tt);
                locmmptr->e++;
            }else{
	printf("[MPL]: unsend data multicast packet\n");
        resend(0, &locmmptr->tt);
	// program another sending
        }
    }else{
	resend(1, &locmmptr->tt);
	printf("Multicast Packet sent!! %d\n",lochbhmptr->seq);
	locmmptr->e++;
        UIP_MCAST6_STATS_ADD(mcast_out);
    }
    uip_clear_buf();
  }else{
   printf("no trasmit e = %u\n",locmmptr->e);
   resend(1, &locmmptr->tt);
   locmmptr->e++;
  }
 data_traitement = 0;
}

static void
data_message_expiration_rea(void *ptr, uint8_t suppress)
{
  data_traitement = 1;
  /* Callback for data message trickle timers */
  locmmptr = ((struct mpl_msg *)ptr);
  if(locmmptr->e > 0) {
    /* Terminate the trickle timer here if we've already expired enough times */
    trickle_timer_stop(&locmmptr->tt);

    return;
  }
    printf("Start rea transmition\n");
   
  if(suppress == TRICKLE_TIMER_TX_OK) { /* Only transmit if not suppressed */
    PRINTF("[MPL]:Data message TX\n");
    PRINTF("[MPL]:Seed ID=");
    LOG_INFO_SEED(locmmptr->seed->seed_id);
    PRINTF("[MPL]:, S=%u, Seq=%u\n", locmmptr->seed->seed_id.s, locmmptr->seq);
    /* Setup the IP Header */
    UIP_IP_BUF->vtc = 0x60;
    UIP_IP_BUF->tcflow = 0;
    UIP_IP_BUF->flow = 0;
    UIP_IP_BUF->proto = UIP_PROTO_HBHO;
    /*UIP_IP_BUF->ttl = MPL_IP_HOP_LIMIT; */
    uip_ip6addr_copy(&UIP_IP_BUF->destipaddr, &locmmptr->seed->domain->data_addr);
    uip_len = UIP_IPH_LEN;
    /* Setup the HBHO Header */
    UIP_EXT_BUF->next = UIP_PROTO_UDP;
    lochbhmptr = UIP_EXT_OPT_FIRST;
    lochbhmptr->type = HBHO_OPT_TYPE_MPL;
    lochbhmptr->flags = 0x00;
    switch(locmmptr->seed->seed_id.s) {
    case 0:
      UIP_EXT_BUF->len = HBHO_S0_LEN / 8;
      lochbhmptr->len = MPL_OPT_LEN_S0;
      HBH_CLR_S(lochbhmptr);
      HBH_SET_S(lochbhmptr, 0);
      uip_len += HBHO_BASE_LEN + HBHO_S0_LEN;
      uip_ext_len += HBHO_BASE_LEN + HBHO_S0_LEN;
      lochbhmptr->padn.opt_type = UIP_EXT_HDR_OPT_PADN;
      lochbhmptr->padn.opt_len = 0x00;
      break;
    case 1:
      UIP_EXT_BUF->len = HBHO_S1_LEN / 8;
      lochbhmptr->len = MPL_OPT_LEN_S1;
      HBH_CLR_S(lochbhmptr);
      HBH_SET_S(lochbhmptr, 1);
      seed_id_host_to_net(&((struct mpl_hbho_s1 *)lochbhmptr)->seed_id, &locmmptr->seed->seed_id);
      uip_len += HBHO_BASE_LEN + HBHO_S1_LEN;
      uip_ext_len += HBHO_BASE_LEN + HBHO_S1_LEN;
      break;
    case 2:
      UIP_EXT_BUF->len = HBHO_S2_LEN / 8;
      lochbhmptr->len = MPL_OPT_LEN_S2;
      HBH_CLR_S(lochbhmptr);
      HBH_SET_S(lochbhmptr, 2);
      seed_id_host_to_net(&((struct mpl_hbho_s2 *)lochbhmptr)->seed_id, &locmmptr->seed->seed_id);
      uip_len += HBHO_BASE_LEN + HBHO_S2_LEN;
      uip_ext_len += HBHO_BASE_LEN + HBHO_S2_LEN;
      ((struct mpl_hbho_s2 *)lochbhmptr)->padn.opt_type = UIP_EXT_HDR_OPT_PADN;
      ((struct mpl_hbho_s2 *)lochbhmptr)->padn.opt_len = 0x00;
      break;
    case 3:
      UIP_EXT_BUF->len = HBHO_S3_LEN / 8;
      lochbhmptr->len = MPL_OPT_LEN_S3;
      HBH_CLR_S(lochbhmptr);
      HBH_SET_S(lochbhmptr, 3);
      seed_id_host_to_net(&((struct mpl_hbho_s3 *)lochbhmptr)->seed_id, &locmmptr->seed->seed_id);
      uip_len += HBHO_BASE_LEN + HBHO_S3_LEN;
      uip_ext_len += HBHO_BASE_LEN + HBHO_S3_LEN;
      ((struct mpl_hbho_s3 *)lochbhmptr)->padn.opt_type = UIP_EXT_HDR_OPT_PADN;
      ((struct mpl_hbho_s3 *)lochbhmptr)->padn.opt_len = 0x00;
      break;
    }
    lochbhmptr->seq = locmmptr->seq;
    if(list_item_next(locmmptr) == NULL) {
      HBH_SET_M(lochbhmptr);
    }
    /* Now insert payload */
    memcpy(((void *)UIP_EXT_BUF) + 8 + UIP_EXT_BUF->len * 8, &locmmptr->data, locmmptr->size);
    uip_len += locmmptr->size;

    UIP_IP_BUF->len[0] = ((uip_len - UIP_IPH_LEN) >> 8);
    UIP_IP_BUF->len[1] = ((uip_len - UIP_IPH_LEN) & 0xff);

    uip_ip6addr_copy(&UIP_IP_BUF->srcipaddr, &locmmptr->srcipaddr);
    tcpip_output(NULL);

     printf("e = %u\n",locmmptr->e);

    if(unsend == 1)
    {
	unsend = 0;
        if(trickle_a(&locmmptr->tt) > 0){
		printf("trickle end a = %u \n",trickle_a(&locmmptr->tt));
	  	resend(1, &locmmptr->tt);
                locmmptr->e++;
            }else{
	printf("[MPL]: unsend data multicast packet\n");
        resend(0, &locmmptr->tt);
	// program another sending
        }
    }else{
	resend(1, &locmmptr->tt);
	printf("Multicast Packet sent!! %d\n",lochbhmptr->seq);
        locmmptr->e++;
        UIP_MCAST6_STATS_ADD(mcast_out);
    }
    uip_clear_buf();

  }else{
  printf("no trasmit e = %u\n",locmmptr->e);
  resend(1, &locmmptr->tt);
  locmmptr->e++;
 }
 data_traitement = 0;
}
static void
mpl_maddr_check(void)
{
  /* Check for new multicast addresses that aren't in our domain set */
  uip_ds6_maddr_t *elem;
  for(elem = &uip_ds6_if.maddr_list[UIP_DS6_MADDR_NB - 1];
      elem >= uip_ds6_if.maddr_list;
      elem--) {
    if(elem->isused && uip_mcast6_get_address_scope(&elem->ipaddr) > UIP_MCAST6_SCOPE_LINK_LOCAL) {
      locdsptr = domain_set_lookup(&elem->ipaddr);
      if(!locdsptr) {
        locdsptr = domain_set_allocate(&elem->ipaddr);
        if(!locdsptr) {
          PRINTF("[MPL]:Failed to allocate domain set in mpl_maddr_check()\n");
        }
      }
    }
  }
  /* Check for domain set addresses that aren't in our maddr table */
  for(locdsptr = &domain_set[MPL_DOMAIN_SET_SIZE - 1]; locdsptr >= domain_set; locdsptr--) {
    if(DOMAIN_SET_IS_USED(locdsptr) && !uip_ds6_maddr_lookup(&locdsptr->data_addr)) {
      domain_set_free(locdsptr);
    }
  }
}
static void
lifetime_timer_expiration(void *ptr)
{
  /* Called once per minute to decrement seed lifetime counters */
  for(locssptr = &seed_set[MPL_SEED_SET_SIZE - 1]; seed_set <= locssptr; locssptr--) {
    if(SEED_SET_IS_USED(locssptr) && locssptr->lifetime == 0) {
      /* Check no timers are running */
      locmmptr = list_head(locssptr->min_seq);
      while(locmmptr != NULL) {
        if(trickle_timer_is_running(&locmmptr->tt)) {
          /* We must keep this seed */
          break;
        }
        locmmptr = list_item_next(locmmptr);
      }
      if(locmmptr == NULL) {
        /* We can now free this seed set */
        PRINTF("[MPL]:Seed ");
        LOG_INFO_SEED(locssptr->seed_id);
        PRINTF("[MPL]: expired. Freeing...\n");
        seed_set_free(locssptr);
      }
    }
    if(locssptr->lifetime > 0) {
      locssptr->lifetime--;
    }
  }
  mpl_maddr_check();
  ctimer_reset(&lifetime_timer);
}
#if MPL_REACTIVE_FORWARDING
static void
icmp_in(void)
{
  printf("icmp in\n");
  static seed_id_t seed_id;
  static uint8_t r; 
  static uint8_t *vector; 
  static uint8_t vector_len; 
  static uint8_t r_missing; 
  static uint8_t l_missing;

#if UIP_CONF_IPV6_CHECKS
  if(!uip_is_addr_mcast_non_routable(&UIP_IP_BUF->destipaddr)) {
    PRINTF("[MPL]:ICMPv6 In, bad dest ");
    PRINT6ADDR(&UIP_IP_BUF->destipaddr);
    PRINTF("\n");
    MPL_STATS_ADD(icmp_bad);
    goto discard;
  }

  if(UIP_ICMP_BUF->type != ICMP6_MPL) {
    PRINTF("[MPL]:ICMPv6 In, bad ICMP type\n");
    MPL_STATS_ADD(icmp_bad);
    goto discard;
  }

  if(UIP_ICMP_BUF->icode != 0) {
    PRINTF("[MPL]:ICMPv6 In, bad ICMP type\n");
    MPL_STATS_ADD(icmp_bad);
    goto discard;
  }

  if(UIP_IP_BUF->ttl != MPL_IP_HOP_LIMIT) {
    PRINTF("[MPL]:ICMPv6 In, bad TTL\n");
    MPL_STATS_ADD(icmp_bad);
    goto discard;
  }
#endif

  PRINTF("[MPL]:MPL ICMP Control Message from");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF("[MPL]: len %u, ext %u\n", uip_len, uip_ext_len);

  MPL_STATS_ADD(icmp_in);

  /* Find the domain that this has come from */
  locdsptr = domain_set_lookup(&UIP_IP_BUF->destipaddr);
  /** if the domain don't exists we well create New MPL Domain **/
  if(!locdsptr) {
    PRINTF("[MPL]:New MPL Domain ");
    PRINT6ADDR(&UIP_IP_BUF->destipaddr);
    PRINTF("\n");
    locdsptr = domain_set_allocate(&UIP_IP_BUF->destipaddr);
    if(!locdsptr) {
      
      printf("[MPL]:Couldn't allocate new domain. Dropping.\n");
      UIP_MCAST6_STATS_ADD(icmp_bad);
      goto discard;
    }
    mpl_control_trickle_timer_start(locdsptr);
  }
  l_missing = 0;
  r_missing = 0;

  /* Iterate over our seed set and check all are present in the remote seed sed */
  /**locsiptr is the payload sent in ICMP Control messages (min_seqno, bm_len_S and seed_id)**/
  locsiptr = (struct seed_info *)UIP_ICMP_PAYLOAD;
  /**the MPL Domain’s Seed Set includes an MPL Seed that does not exist in the MPL Control Message  **/
  for(locssptr = &seed_set[MPL_SEED_SET_SIZE - 1]; locssptr >= seed_set; locssptr--) {
    if(SEED_SET_IS_USED(locssptr) && locssptr->domain == locdsptr) {
      /**if the seed exists in this domain**/
      PRINTF("[MPL]:Checking remote for seed ");
      LOG_INFO_SEED(locssptr->seed_id);
      PRINTF("\n");

      while(locsiptr <
            (struct seed_info *)((void *)UIP_ICMP_PAYLOAD + uip_len - uip_l2_l3_icmp_hdr_len)) {
        switch(SEED_INFO_GET_S(locsiptr)) { /**S identifies the length of the seed-id**/
        case 0:
          seed_id_net_to_host(&seed_id, &UIP_IP_BUF->srcipaddr, 0);  /**Convert a seed id in network order header format and length S to internal representation.*/
          locsiptr = ((void *)locsiptr) + sizeof(struct seed_info) + SEED_INFO_GET_LEN(locsiptr);
          if(seed_id_cmp(&seed_id, &locssptr->seed_id)) {
            goto seed_present;
          }
          break;
        case 1:
          seed_id_net_to_host(&seed_id, &((struct seed_info_s1 *)locsiptr)->seed_id, 1);
          locsiptr = ((void *)locsiptr) + sizeof(struct seed_info_s1) + SEED_INFO_GET_LEN(locsiptr);
          if(seed_id_cmp(&seed_id, &locssptr->seed_id)) {
            goto seed_present;
          }
          break;
        case 2:
          seed_id_net_to_host(&seed_id, &((struct seed_info_s2 *)locsiptr)->seed_id, 2);
          locsiptr = ((void *)locsiptr) + sizeof(struct seed_info_s2) + SEED_INFO_GET_LEN(locsiptr);
          if(seed_id_cmp(&seed_id, &locssptr->seed_id)) {
            goto seed_present;
          }
          break;
        case 3:
          seed_id_net_to_host(&seed_id, &((struct seed_info_s3 *)locsiptr)->seed_id, 3);
          locsiptr = ((void *)locsiptr) + sizeof(struct seed_info_s3) + SEED_INFO_GET_LEN(locsiptr);
          if(seed_id_cmp(&seed_id, &locssptr->seed_id)) {
            goto seed_present;
          }
          break;
        }
      }
      /* If we made it this far, the seed is missing from the remote. Reset all message timers */
      /**The MPL Control Message includes an MPL Seed that does not exist in the MPL Domain’s Seed Set**/
      PRINTF("[MPL]:Remote is missing seed ");
      LOG_INFO_SEED(locssptr->seed_id);
      PRINTF("[MPL]:\n");
      r_missing = 1;
      if(list_head(locssptr->min_seq) != NULL) {
        for(locmmptr = list_head(locssptr->min_seq); locmmptr != NULL; locmmptr = list_item_next(locmmptr)) {
          PRINTF("[MPL]:Resetting timer for messages\n");
          if(!trickle_timer_is_running(&locmmptr->tt)) {
            PRINTF("[MPL]:Starting timer for messages\n");
            mpl_data_trickle_timer_start_rea(locmmptr);
          }
	        printf("0 mpl_trickle_timer_inconsistency seq=%u\n", locmmptr->seq);
          mpl_trickle_timer_inconsistency(locmmptr);
        }
      }
      /* Otherwise we jump here and continute */
seed_present:
      continue;
    }
  }

  /* Iterate over remote seed info and they're present locally. Additionally check messages match */
  locsiptr = (struct seed_info *)UIP_ICMP_PAYLOAD;
  /**The MPL Control Message includes an MPL Seed that does not exist in the MPL Domain’s Seed Set**/
  while(locsiptr <
        (struct seed_info *)((void *)UIP_ICMP_PAYLOAD + uip_len - uip_l2_l3_icmp_hdr_len)) {
    /* Extract the seed id */
    if(SEED_INFO_GET_S(locsiptr) > 0) {
      seed_id_net_to_host(&seed_id, &((struct seed_info_s1 *)locsiptr)->seed_id, SEED_INFO_GET_S(locsiptr));
    } else {
      /* Always set as S3 because it will never be us */
      seed_id_net_to_host(&seed_id, &UIP_IP_BUF->srcipaddr, 3);
    }

    PRINTF("[MPL]:Control Message for Seed Id: ");
    LOG_INFO_SEED(seed_id);
    PRINTF("[MPL]:Min Seq Number: %u, %u bytes\n", locsiptr->min_seqno, SEED_INFO_GET_LEN(locsiptr));

    /* Do we have this seed? */
    locssptr = seed_set_lookup(&seed_id, locdsptr);
    if(!locssptr) {
      PRINTF("[MPL]:Unknown seed in seed info\n");
      /** We don't know this seed **/
      l_missing = 1;
      goto next;
    }
     /**the seed exists in the Seed Set**/
    /* Work out where remote bit vector starts */
    vector_len = SEED_INFO_GET_LEN(locsiptr) * 8;
    
    switch(SEED_INFO_GET_S(locsiptr)) {
    case 0:
      vector = ((void *)locsiptr) + sizeof(struct seed_info);
      break;
    case 1:
      vector = ((void *)locsiptr) + sizeof(struct seed_info_s1);
      break;
    case 2:
      vector = ((void *)locsiptr) + sizeof(struct seed_info_s2);
      break;
    case 3:
      vector = ((void *)locsiptr) + sizeof(struct seed_info_s3);
      break;
    }

    /* Potential quick resolution here */ 
    locmmptr = list_head(locssptr->min_seq);
    if(locmmptr == NULL) {
      
      /* We have nothing! -- no message in the buffer for this Seed*/
      if(vector[0] > 0) {
        /* They have something! */
        l_missing = 1;
      }
      goto next;
    }
    /**
     * Work out what offset the local or remote message set need so that the
     * sequence numbers match up
     */
/**Le seed existe et il existe quelque messages
**/
    r = 0;
    if(locmmptr->seq != locsiptr->min_seqno) {
      if(SEQ_VAL_IS_GT(locmmptr->seq, locsiptr->min_seqno)) {
        while(locmmptr->seq != SEQ_VAL_ADD(locsiptr->min_seqno, r) && r <= vector_len) {
          r++;
        }
      } else {
        while(locmmptr != NULL && locmmptr->seq != locsiptr->min_seqno) {
          locmmptr = list_item_next(locmmptr);
        }
      }

      /* There is no overlap in message sets */
      if(r > vector_len || locmmptr == NULL) {
        PRINTF("[MPL]:Seed sets of local and remote have no overlap.\n");
        /* Work out who is behind who */
        
        locmmptr = list_head(locssptr->min_seq);
         while(list_item_next(locmmptr) != NULL) {
           locmmptr = list_item_next(locmmptr);
        }
        r = vector_len;
        while(!BIT_VECTOR_GET_BIT(vector, r)) {
          r--;
        }

        if(SEQ_VAL_IS_GT(locmmptr->seq, SEQ_VAL_ADD(locsiptr->min_seqno, r))) {
          /* Our max (cor: min) sequence number is greater than their max sequence number */
          printf("[MPL]:Our max (min) sequence number is greater than their max sequence number\n");
          r_missing = 1;
          /* Additionally all data message timers in set if r is behind us */
          if(list_head(locssptr->min_seq) != NULL) {
            for(locmmptr = list_head(locssptr->min_seq); locmmptr != NULL; locmmptr = list_item_next(locmmptr)) {
              if(!trickle_timer_is_running(&locmmptr->tt)) {
                mpl_data_trickle_timer_start_rea(locmmptr);
              }
	               printf("1 mpl_trickle_timer_inconsistency seq=%u\n", locmmptr->seq);
              mpl_trickle_timer_inconsistency(locmmptr);
            }
          }
        } else {
             l_missing = 1;             
	           printf("[MPL]:Our max sequence number is less than their min sequence number\n");
        }
        goto next;
      }
    }
	/**
		The MPL Control Message indicates that the neighbor has an MPL
		Data Message in its Buffered Message Set with sequence number
		greater than MinSequence (i.e., the i-th bit is set to 1 and
		min-seqno + i > MinSequence) and is not included in the MPL
		Domain’s Buffered Message Set.
	**/
    /**
     * If we've made it this far, our sets overlap and we can work out specific
     *   messages that may be missing from each set.
     */
    do {
      /* This won't occur on first iteration */
      /* Resyncronise our pointers to local and remote messages after previous iteration */
      while(locmmptr->seq != SEQ_VAL_ADD(locsiptr->min_seqno, r)) {
        /**
         * If we enter this loop it means there is a gap in local sequence numbers.
         *  Check that same gap exists in the remote set.
         */
        if(BIT_VECTOR_GET_BIT(vector, r)) {
          /* We are missing a message. Reset timer */        
           l_missing = 1;
        }
        r++;
      }
      /* At this point the local pointer and remote pointer will be in sync */

      /* Check whether the remote is missing the current message */
      if(!BIT_VECTOR_GET_BIT(vector, r)) {
        /* Local message is missing from remote set. Reset control and data timers */
        printf("[MPL]:Remote is missing seq=%u\n", locmmptr->seq);
        r_missing = 1;
        if(!trickle_timer_is_running(&locmmptr->tt)) {
          mpl_data_trickle_timer_start_rea(locmmptr);
        }
	      printf("2 mpl_trickle_timer_inconsistency seq=%u\n", locmmptr->seq);
        mpl_trickle_timer_inconsistency(locmmptr);
      }

      /* Now increment our pointers */
      r++;
      locmmptr = list_item_next(locmmptr);
      /* These are then resyncronised at the top of the loop */
    } while(locmmptr != NULL && r <= vector_len);

    /* If we have stopped short of either message set then we may have inconsistencies */
    if(locmmptr != NULL || r < vector_len) {
      /**
       * We have reached the end of local set, the remainder of the remote set should
       *  be zero else local is missing a message.
       */
      while(r < vector_len) {
        if(BIT_VECTOR_GET_BIT(vector, r)) {
           /* We are missing a message */
           printf("[MPL]:We are missing seq=%u which is greater than our max seq number\n", SEQ_VAL_ADD(locsiptr->min_seqno, r));
           l_missing = 1;
        }
        r++;
      }
    } else if(r >= vector_len && locmmptr != NULL) {
      /* We have reached the end of the remote set.
       *  Any remaining messages are missing and should be reset.
       */
      while(locmmptr != NULL) {
        printf("[MPL]:Remote is missing all above seq=%u\n", locmmptr->seq);
        if(!trickle_timer_is_running(&locmmptr->tt)) {
          mpl_data_trickle_timer_start_rea(locmmptr);
        }
	printf("3 mpl_trickle_timer_inconsistency seq=%u\n", locmmptr->seq);
        mpl_trickle_timer_inconsistency(locmmptr);
        r_missing = 1;
        locmmptr = list_item_next(locmmptr);
      }
    }
    /* Now point to next seed info */
next:
    switch(SEED_INFO_GET_S(locsiptr)) {
    case 0:
      locsiptr = ((void *)locsiptr) + sizeof(struct seed_info) + SEED_INFO_GET_LEN(locsiptr);
      break;
    case 1:
      locsiptr = ((void *)locsiptr) + sizeof(struct seed_info_s1) + SEED_INFO_GET_LEN(locsiptr);
      break;
    case 2:
      locsiptr = ((void *)locsiptr) + sizeof(struct seed_info_s2) + SEED_INFO_GET_LEN(locsiptr);
      break;
    case 3:
      locsiptr = ((void *)locsiptr) + sizeof(struct seed_info_s3) + SEED_INFO_GET_LEN(locsiptr);
      break;
    }
  }


  /* Now sort out control message timers */
  if(l_missing && !trickle_timer_is_running(&locdsptr->tt)) {
    mpl_control_trickle_timer_start(locdsptr);
  }
  /**l_missing this node has a lack in the buffer**/
  /**r_missing the source of ICMPv6 message has a lack in the buffer**/
  /**
      MPL defines an "inconsistent" transmission as receiving
    an MPL Control Message that results in a determination that either
    the receiving or transmitting node has at least one new MPL Data
    Message to offer.
  **/
  if(l_missing) { // Enhanced REA
    PRINTF("[MPL]:Inconsistency detected l=%u, r=%u\n", l_missing, r_missing);
    if(trickle_timer_is_running(&locdsptr->tt)) {
      mpl_trickle_timer_inconsistency(locdsptr);
    printf("mpl_ICMP_trickle_timer_inconsistency\n");
    }
  } else {
    if(!r_missing) {
      PRINTF("[MPL]:Domain is consistent \n");
      printf("mpl_control_trickle_timer_consistancy\n");
      trickle_timer_consistency(&locdsptr->tt);
    }
  }


discard:
  uip_len = 0;
  uip_clear_buf();
  return;
}
#endif
static uint8_t
accept(uint8_t in)
{
  static seed_id_t seed_id;
  static uint16_t seq_val; //sequence number of the Data Message
  static uint8_t S; // type of seed ID
  static struct mpl_msg *mmiterptr;
  static struct uip_ext_hdr *hptr;

  printf("[MPL]:Multicast I/O\n");

#if UIP_CONF_IPV6_CHECKS
  if(uip_is_addr_mcast_non_routable(&UIP_IP_BUF->destipaddr)) {
    PRINTF("[MPL]:Mcast I/O, bad destination\n");
    UIP_MCAST6_STATS_ADD(mcast_bad);
    return UIP_MCAST6_DROP;
  }
  /*
   * Abort transmission if the v6 src is unspecified. This may happen if the
   * seed tries to TX while it's still performing DAD or waiting for a prefix
   */
  if(uip_is_addr_unspecified(&UIP_IP_BUF->srcipaddr)) {
    PRINTF("[MPL]:Mcast I/O, bad source\n");
    UIP_MCAST6_STATS_ADD(mcast_bad);
    return UIP_MCAST6_DROP;
  }
#endif

  /* Check the Next Header field: Must be HBHO */
  if(UIP_IP_BUF->proto != UIP_PROTO_HBHO) {
    PRINTF("[MPL]:Mcast I/O, bad proto\n");
    PRINTF("[MPL]:Next Proto was %u\n", UIP_IP_BUF->proto);
    UIP_MCAST6_STATS_ADD(mcast_bad);
    return UIP_MCAST6_DROP;
  } else {
    /* Check the Option Type */
    if(UIP_EXT_OPT_FIRST->type != HBHO_OPT_TYPE_MPL) {
      PRINTF("[MPL]:Mcast I/O, bad HBHO type\n");
      UIP_MCAST6_STATS_ADD(mcast_bad);
      return UIP_MCAST6_DROP;
    }
  }
  lochbhmptr = UIP_EXT_OPT_FIRST;

  PRINTF("[MPL]:HBHO T=%u, L=%u, M=%u, V=%u, S=%u, SEQ=0x%x\n",lochbhmptr->type, lochbhmptr->len, HBH_GET_M(lochbhmptr), HBH_GET_V(lochbhmptr), HBH_GET_S(lochbhmptr),lochbhmptr->seq);

#if UIP_MCAST6_STATS
  if(in == MPL_DGRAM_IN) {
    UIP_MCAST6_STATS_ADD(mcast_in_all);
  }
#endif
  /* Do a check on the V bit */
  if(HBH_GET_V(lochbhmptr)) {
    /* The V bit MUST be zero otherwise we drop the message */
    PRINTF("[MPL]:Invalid V bit - dropping...\n");
    return UIP_MCAST6_DROP;
  }
  /* Is this for a known seed and domain? */
  S = HBH_GET_S(lochbhmptr);
  PRINTF("[MPL]:Incoming message S value = %u\n", S);
/**recuperer le seed id**/
  if(S == 0) {
    /* Seed ID is the IPV6 Source Address */
    seed_id_net_to_host(&seed_id, &UIP_IP_BUF->srcipaddr, S);
  } else {
    /**
     * Seed ID is embedded in the header where padding would otherwise be.
     * Since we're only interested in the address the specific s1/s2/s3
     * type doesn't matter.
     */
    seed_id_net_to_host(&seed_id, &((struct mpl_hbho_s1 *)lochbhmptr)->seed_id, S);
  }

  PRINTF("[MPL]:MPL Domain is ");
  PRINT6ADDR(&UIP_IP_BUF->destipaddr);
  PRINTF("\n");

  /* First check the MPL Domain */
  locdsptr = domain_set_lookup(&UIP_IP_BUF->destipaddr);

/**if MPL_DGRAM_OUT: pas besoin de cette étape puisque le domaine existe**/
  if(!locdsptr) {
    locdsptr = domain_set_allocate(&UIP_IP_BUF->destipaddr);
    PRINTF("[MPL]:New MPL Domain ");
    PRINT6ADDR(&UIP_IP_BUF->destipaddr);
    PRINTF("[MPL]:\n");
    if(!locdsptr) {
      PRINTF("[MPL]:Couldn't add to MPL Domain Set. Dropping.\n");
      UIP_MCAST6_STATS_ADD(mcast_dropped);
      return UIP_MCAST6_DROP;
    }
#if MPL_REACTIVE_FORWARDING // after domain allocation
    /* Setup new MPL Domain */ 
    if(!trickle_timer_config(&locdsptr->tt,
                             MPL_CONTROL_MESSAGE_IMIN,
                             MPL_CONTROL_MESSAGE_IMAX,
                             MPL_CONTROL_MESSAGE_K)) {
      PRINTF("[MPL]:Unable to configure trickle timer for domain. Dropping,...\n");
      domain_set_free(locdsptr);
      return UIP_MCAST6_DROP;
    }

  printf("Start reactive processing - the first data received\n");
  #if MPL_CONTROL_MESSAGE_TIMER_EXPIRATIONS > 0
  if(!trickle_timer_is_running(&locdsptr->tt)) {
    mpl_control_trickle_timer_start(locdsptr);
  } 
  #endif
#endif
  }

  /* Now lookup this seed */
  locssptr = seed_set_lookup(&seed_id, locdsptr);

  seq_val = lochbhmptr->seq;

  if(locssptr) { 
    if(SEQ_VAL_IS_LT(seq_val, locssptr->min_seqno)) {
      /* Too old, drop */
      PRINTF("[MPL]:Too old\n");
      UIP_MCAST6_STATS_ADD(mcast_dropped);
      return UIP_MCAST6_DROP;
    }

    if(list_head(locssptr->min_seq) != NULL) {
      for(locmmptr = list_head(locssptr->min_seq); locmmptr != NULL; locmmptr = list_item_next(locmmptr)) {
        if(SEQ_VAL_IS_EQ(seq_val, locmmptr->seq)) {
          /* Seen before , drop */
          printf("[MPL]:Seen before\n");
	    /** MPL defines a MPL Data Message "consistent" transmission as receiving an
               MPL Data Message that has the same MPL Domain Address, seed-id,
               and sequence value as the MPL Data Message managed by the
               Trickle timer.
            **/
          printf("mpl_data_trickle_timer_consistancy\n");
	  trickle_timer_consistency(&locmmptr->tt);
          if(HBH_GET_M(lochbhmptr) && list_item_next(locmmptr) != NULL) {
            /**  MPL defines an MPL Data Message "inconsistent" transmission as receiving
                an MPL Data Message that has the same MPL Domain Address, seed-id
                value, and the M flag set, but has a sequence value less than that
                of the MPL Data Message managed by the Trickle timer
            **/
             locmmptr = list_item_next(locmmptr);
            while (locmmptr != NULL) {
	            printf("M_flag: mpl_trickle_timer_inconsistency\n");
              mpl_trickle_timer_inconsistency(locmmptr);
              locmmptr = list_item_next(locmmptr);
            }

          }
          UIP_MCAST6_STATS_ADD(mcast_dropped);
          return UIP_MCAST6_DROP;
        }
      }
    }    
  }
  /* We have not seen this message before */

  /* Allocate a seed set if we have to */
  /**only for MPL_DGRAM_IN**/
  if(!locssptr) {
    locssptr = seed_set_allocate();
    PRINTF("[MPL]:New seed\n");
    if(!locssptr) {
      /* Couldn't allocate seed set, drop */
      PRINTF("[MPL]:Failed to allocate seed set\n");
      UIP_MCAST6_STATS_ADD(mcast_dropped);
      return UIP_MCAST6_DROP;
    }
    memset(locssptr, 0, sizeof(struct mpl_seed));
    LIST_STRUCT_INIT(locssptr, min_seq);
    seed_id_cpy(&locssptr->seed_id, &seed_id);
    locssptr->domain = locdsptr;
  }

  /* Allocate a buffer */
  locmmptr = buffer_allocate();
  if(!locmmptr) {
    PRINTF("[MPL]:Buffer allocation failed. Reclaiming...\n");
    locmmptr = buffer_reclaim();
    if(!locmmptr) {
      PRINTF("[MPL]:Buffer reclaim failed. Dropping...\n");
      UIP_MCAST6_STATS_ADD(mcast_dropped);
      return UIP_MCAST6_DROP;
    }
  }

  /* We have a domain set, a seed set, and we have a buffer. Accept this message */
  PRINTF("[MPL]:Message from seed ");
  LOG_INFO_SEED(locssptr->seed_id);
  PRINTF("[MPL]:\n");

  /* Set the source IP of the message */
  uip_ip6addr_copy(&locmmptr->srcipaddr, &UIP_IP_BUF->srcipaddr);

#if UIP_MCAST6_STATS
  if(in == MPL_DGRAM_IN) {
    UIP_MCAST6_STATS_ADD(mcast_in_unique);
  }
#endif

  /* Find the start of the payload */
  hptr = (struct uip_ext_hdr *)UIP_EXT_BUF;
  while(hptr->next != UIP_PROTO_UDP) {
    hptr = ((void *)hptr) + hptr->len * 8 + 8;
  }
  hptr = ((void *)hptr) + hptr->len * 8 + 8;
  locmmptr->size = uip_len - UIP_IPH_LEN - uip_ext_len;
  memcpy(&locmmptr->data, hptr, locmmptr->size);
  locmmptr->seq = seq_val;
  locmmptr->seed = locssptr;
  if(!trickle_timer_config(&locmmptr->tt,
                           MPL_DATA_MESSAGE_IMIN,
                           MPL_DATA_MESSAGE_IMAX,
                           MPL_DATA_MESSAGE_K)) {
    PRINTF("[MPL]:Failed to configure timer for message. Dropping...\n");
    buffer_free(locmmptr);
    return UIP_MCAST6_DROP;
  }

  /* Place the message into the buffered message linked list */
  if(list_head(locssptr->min_seq) == NULL) {
    list_push(locssptr->min_seq, locmmptr);
    locssptr->min_seqno = 1;
  } else {
if(SEQ_VAL_IS_LT(locmmptr->seq,((struct mpl_msg *)list_head(locssptr->min_seq))->seq))
{
  printf("liste push\n");
  list_push(locssptr->min_seq,locmmptr);
}else{
    for(mmiterptr = list_head(locssptr->min_seq); mmiterptr != NULL; mmiterptr = list_item_next(mmiterptr)) {
      if(list_item_next(mmiterptr) == NULL
         || (SEQ_VAL_IS_GT(locmmptr->seq, mmiterptr->seq) && SEQ_VAL_IS_LT(locmmptr->seq, ((struct mpl_msg *)list_item_next(mmiterptr))->seq))) {
        list_insert(locssptr->min_seq, mmiterptr, locmmptr);
        break;
      }
    }
   }
  }

  locssptr->count++;

/**If PROACTIVE_FORWARDING is TRUE, the MPL Forwarder MUST initialize and start a Trickle timer for the MPL Data Message**/
#if MPL_PROACTIVE_FORWARDING
  /* Start Forwarding the message */
  mpl_data_trickle_timer_start(locmmptr);
#endif

  PRINTF("[MPL]:Min Seq Number=%u, %u values\n", locssptr->min_seqno, locssptr->count);
  /**Reset the Lifetime of the corresponding Seed Set entry to SEED_SET_ENTRY_LIFETIME**/
  locssptr->lifetime = MPL_SEED_SET_ENTRY_LIFETIME;

  /* Deliver if necessary */
  return UIP_MCAST6_ACCEPT;
}
static void
out(void)
{
  /* Check we know our seed ID */
  if(local_seed_id.s == MPL_SEED_ID_UNKNOWN) {
    update_seed_id();
    if(local_seed_id.s == MPL_SEED_ID_UNKNOWN) {
      PRINTF("[MPL]:Our seed ID is not yet known.\n");
      goto drop;
    }
  }

  /* Check we have enough space for the options header */
  if(uip_len + HBHO_TOTAL_LEN > UIP_BUFSIZE) {
    PRINTF("[MPL]:Multicast Out can not add HBHO. Packet too long\n");
    goto drop;
  }

  /* Slide 'right' by HBHO_TOTAL_LEN bytes */
  memmove(UIP_EXT_BUF_NEXT, UIP_EXT_BUF, uip_len - UIP_IPH_LEN);
  memset(UIP_EXT_BUF, 0, HBHO_TOTAL_LEN);

  /* Insert the option header into the packet and set it's length */
  /* This depends entirely on our seed ID size */
  UIP_EXT_BUF->next = UIP_IP_BUF->proto;
#if MPL_SEED_ID_TYPE == 0
  UIP_EXT_BUF->len = HBHO_S0_LEN / 8;
#elif MPL_SEED_ID_TYPE == 1
  UIP_EXT_BUF->len = HBHO_S1_LEN / 8;
#elif MPL_SEED_ID_TYPE == 2
  UIP_EXT_BUF->len = HBHO_S2_LEN / 8;
#elif MPL_SEED_ID_TYPE == 3
  UIP_EXT_BUF->len = HBHO_S3_LEN / 8;
#endif

  /* Get a reference to the HBHO and set the type */
  lochbhmptr = UIP_EXT_OPT_FIRST;
  lochbhmptr->type = HBHO_OPT_TYPE_MPL;
  lochbhmptr->flags = 0x00;
  HBH_CLR_S(lochbhmptr);
  HBH_SET_S(lochbhmptr, MPL_SEED_ID_TYPE);
  HBH_CLR_V(lochbhmptr);
#if MPL_SEED_ID_TYPE == 0
  lochbhmptr->len = MPL_OPT_LEN_S0;
  /* In this case the Seed ID is our IPV6 address */
  lochbhmptr->padn.opt_type = UIP_EXT_HDR_OPT_PADN;
  lochbhmptr->padn.opt_type = 0x00;
#elif MPL_SEED_ID_TYPE == 1
  lochbhmptr->len = MPL_OPT_LEN_S1;
  seed_id_host_to_net(&((struct mpl_hbho_s1 *)lochbhmptr)->seed_id, &local_seed_id);
#elif MPL_SEED_ID_TYPE == 2
  lochbhmptr->len = MPL_OPT_LEN_S2;
  seed_id_host_to_net(&((struct mpl_hbho_s2 *)lochbhmptr)->seed_id, &local_seed_id);
  ((struct mpl_hbho_s2 *)lochbhmptr)->padn.opt_type = UIP_EXT_HDR_OPT_PADN;
  ((struct mpl_hbho_s2 *)lochbhmptr)->padn.opt_len = 0x00;
#elif MPL_SEED_ID_TYPE == 3
  lochbhmptr->len = MPL_OPT_LEN_S3;
  seed_id_host_to_net(&((struct mpl_hbho_s3 *)lochbhmptr)->seed_id, &local_seed_id);
  ((struct mpl_hbho_s3 *)lochbhmptr)->padn.opt_type = UIP_EXT_HDR_OPT_PADN;
  ((struct mpl_hbho_s3 *)lochbhmptr)->padn.opt_len = 0x00;
#endif

  /* Set the sequence ID */
  last_seq = SEQ_VAL_ADD(last_seq, 1);
  lochbhmptr->seq = last_seq;
  HBH_SET_M(lochbhmptr);

  uip_ext_len += HBHO_TOTAL_LEN;
  uip_len += HBHO_TOTAL_LEN;

  /* Update the proto and length field in the v6 header */
  UIP_IP_BUF->proto = UIP_PROTO_HBHO;
  UIP_IP_BUF->len[0] = ((uip_len - UIP_IPH_LEN) >> 8);
  UIP_IP_BUF->len[1] = ((uip_len - UIP_IPH_LEN) & 0xff);

  PRINTF("[MPL]:Multicast Out\n");
  PRINTF("[MPL]:HBHO: Next Header=0x%x, Header Len (exc. 1st 8 bytes)=%u\n", UIP_EXT_BUF->next, UIP_EXT_BUF->len);
  PRINTF("[MPL]:MPL Option Type 0x%x: Len=%u, S=%u, M=%u, V=%u, Seq=0x%x\n",lochbhmptr->type, lochbhmptr->len, HBH_GET_S(lochbhmptr),HBH_GET_M(lochbhmptr), HBH_GET_V(lochbhmptr), lochbhmptr->seq);

  /*
   * We need to remember this message and advertise it in subsequent ICMP
   * messages. Otherwise, our neighs will think we are inconsistent and will
   * bounce it back to us.
   *
   * Queue this message but don't set its MUST_SEND flag. We reset the trickle
   * timer and we send it immediately. We then set uip_len = 0 to stop the core
   * from re-sending it.
   */
  if(accept(MPL_DGRAM_OUT)) {//MPL_DGRAM_OUT == 0
    printf("Multicast Packet sent!! %d\n",lochbhmptr->seq);
    tcpip_output(NULL); //return 1
    UIP_MCAST6_STATS_ADD(mcast_out);
  }

drop:
  uip_slen = 0;
  uip_clear_buf();
}
static uint8_t
in(void)
{  PRINTF("[MPL]:The IN function\n");
  if(!uip_ds6_is_my_maddr(&UIP_IP_BUF->destipaddr)) {
    PRINTF("[MPL]:Not in our domain. No further processing\n");
    return UIP_MCAST6_DROP;
  }
  /*
   * We call accept() which will sort out caching and forwarding. Depending
   * on accept()'s return value, we then need to signal the core
   * whether to deliver this to higher layers
   */
  if(accept(MPL_DGRAM_IN) == UIP_MCAST6_DROP) {
    PRINTF("[MPL]:Packet dropped\n");
    return UIP_MCAST6_DROP;
  } else {
    PRINTF("[MPL]:Ours. Deliver to upper layers\n");

    UIP_MCAST6_STATS_ADD(mcast_in_ours);
    return UIP_MCAST6_ACCEPT;
  }

}
static void
init(void)
{
  PRINTF("[MPL]:Multicast Protocol for Low Power and Lossy Networks - RFC7731\n");

  /* Clear out all sets */
  memset(domain_set, 0, sizeof(struct mpl_domain) * MPL_DOMAIN_SET_SIZE);
  memset(seed_set, 0, sizeof(struct mpl_seed) * MPL_SEED_SET_SIZE);
  memset(buffered_message_set, 0, sizeof(struct mpl_msg) * MPL_BUFFERED_MESSAGE_SET_SIZE);
#if MPL_REACTIVE_FORWARDING
  /* Register the ICMPv6 input handler */
  uip_icmp6_register_input_handler(&mpl_icmp_handler);
#endif
  update_seed_id();

  /* Init MPL Stats */
  MPL_STATS_INIT();
  UIP_MCAST6_STATS_INIT(&stats);

#if MPL_SUB_TO_ALL_FORWARDERS
  /* Subscribe to the All MPL Forwarders Address by default */
  ALL_MPL_FORWARDERS(&all_forwarders, UIP_MCAST6_SCOPE_REALM_LOCAL);
  if(!uip_ds6_maddr_add(&all_forwarders)) {
    PRINTF("[MPL]:Failed to subscribe to All Forwarders MPL Address\n");
  }else{
    PRINTF("[MPL]:Subscribe to All Forwarders MPL Address\n");
  }
#endif
  mpl_maddr_check();

  /* Setup Minute lifetime timer */
  ctimer_set(&lifetime_timer, CLOCK_SECOND * 60, lifetime_timer_expiration, NULL);
}
/*---------------------------------------------------------------------------*/
/**
 * \brief The MPL engine driver
 */
const struct uip_mcast6_driver mpl_driver = {
  "MPL",
  init,
  out,
  in
};
/*---------------------------------------------------------------------------*/
/** @} */
