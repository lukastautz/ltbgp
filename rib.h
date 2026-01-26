#ifndef INCLUDE_RIB
#define INCLUDE_RIB

#include "include.h"
#include "bgp.h"

extern struct bgp_main_s bgp;

struct PADDED rib_subnet_s {
    uint8 subnet_length;
    uint8 ipv6[6]; // max /48
    uint8 padding;
};

union PADDED rib_subnet_u {
    struct rib_subnet_s subnet;
    uint64 value;
};

struct rib_route_s {
    uint8 peer_id;
    float pref;
    uint8 nexthop[16];
};

struct value_s {
    union rib_subnet_u subnet;
    uint8 route_count;
    uint8 best_route_peer_id;
    struct rib_route_s *routes;
    struct value_s *next;
};

#include "kernel_routing.h"

void hashtable_init(void);
void hashtable_remove_route(union rib_subnet_u s, uint8 peer_id);
void hashtable_remove_peer(uint8 peer_id);
void hashtable_update_peer_id(uint8 peer_id_old, uint8 peer_id_new);
void hashtable_add_route(union rib_subnet_u s, uint8 peer_id, float pref, uint8 *nexthop);

#endif