#ifndef INCLUDE_BGP
#define INCLUDE_BGP

#include "include.h"
#include "bgp_message.h"
#include "rib.h"

void *alloc(uint32 bytes);
void *safe_realloc(void *ptr, uint32 bytes);
char *safe_strdup(char *str);

struct bgp_main_s {
    uint16 local_asn;
    uint32 local_asn_32bit;
    int log_fd;
    int netlink_fd;
    uint8 routing_table_id;
    uint32 identifier;
    uint16 status_port;
    uint8 neighbor_count;
    struct bgp_neighbor_s *neighbors;
    uint16 announcing_group_count;
    struct bgp_announcing_group_s *announcing_groups;
    uint16 route_count;
    struct bgp_route_s *routes;
    bool has_non_default_route;
};

enum bgp_neighbor_state_e {
    BGP_NEIGHBOR_SENDING_UPDATE = 1,
    BGP_NEIGHBOR_SENDING_OPEN = 2,
    BGP_NEIGHBOR_SENDING_KEEPALIVE = 3,
    BGP_NEIGHBOR_SENDING_NOTIFICATION = 4,
    BGP_NEIGHBOR_CONNECTING = 5,
    BGP_NEIGHBOR_DISCONNECTED,
    BGP_NEIGHBOR_CONNECTED,
    BGP_NEIGHBOR_FAILED
};

struct bgp_neighbor_s {
    char *name;
    uint8 id;
    uint16 hold_time;
    uint64 routelimit;
    char *if_name;
    unsigned int if_index;
    uint8 local_ip[16];
    uint8 remote_ip[16];
    uint16 remote_asn;
    uint32 remote_asn_32bit;
    uint8 *md5_password;
    uint8 md5_password_length;
    bool only_default_route;
    uint8 multihop;
    uint8 gateway[16]; // if multihop > 1
    uint16 localpref;
    uint16 local_routes_total;
    uint8 recv_buf[32768];
    uint8 send_buf[4096];

    uint8 failure_count;

    uint16 used_hold_time;
    bool supports_32bit;

    int tcp_fd;
    bool received_open;
    uint16 local_routes_sent;
    uint64 routes_count;
    uint64 installed_routes_count;
    uint16 recv_bytes;
    uint16 sent_bytes;
    uint16 total_bytes_to_send;

    time_t connected_at;
    time_t disconnected_at;

    time_t last_keepalive_received;
    time_t last_keepalive_sent;

    time_t time_started_sending;

    enum bgp_neighbor_state_e state;
    struct bgp_message_validator_s validator;

    uint8 *locally_withdrawn_routes_raw;
    uint16 locally_withdrawn_routes_length;
};

struct bgp_route_s {
    uint8 prefix_length;
    uint8 *prefix;
    uint16 bgp_announcing_group_id;
};

struct bgp_announcing_group_s {
    char *name;
    struct bgp_announcement_specs_s *announcement_specs; // as many elements as there are peers
};

struct bgp_announcement_specs_s {
    bool announce;
    uint8 communities_count;
    uint32 *communities; // 32 bit per community, so sizeof(communities) = 2 * communities_count
    uint8 large_communities_count;
    uint32 *large_communities; // 96 bit per community, so sizeof(large_communities) = 3 * large_communities_count
    uint8 prepend_n_times;
};

#endif
