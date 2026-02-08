#include "rib.h"

static struct value_s **hashtable;

uint32 get_hash(union rib_subnet_u key) {
    if (!bgp.has_non_default_route)
        return 0;
    uint32_t h = 0x9e3779b9;
    h ^= key.subnet.subnet_length;
    h *= 0x85ebca6b;
    h ^= h >> 13;    
    h ^= ((uint32_t)key.subnet.ipv6[0] << 24) | ((uint32_t)key.subnet.ipv6[1] << 16) | ((uint32_t)key.subnet.ipv6[2] << 8) | ((uint32_t)key.subnet.ipv6[3]);
    h *= 0xc2b2ae35;
    h ^= h >> 16;
    h ^= ((uint32_t)key.subnet.ipv6[4] << 24) | ((uint32_t)key.subnet.ipv6[5] << 16);
    h *= 0x85ebca6b;
    h ^= h >> 13;
    return h % 1000000;
}

void hashtable_init(void) {
    uint32 s = 1000000;
    if (!bgp.has_non_default_route)
        s = 1;
    hashtable = (struct value_s **)alloc(s * sizeof(struct value_s *));
    memset(hashtable, 0, s * sizeof(struct value_s *));
}

struct value_s *hashtable_get_add(union rib_subnet_u s) {
    uint32 id = get_hash(s);
    struct value_s *v = hashtable[id];
    if (v == NULL) {
        struct value_s *added = (struct value_s *)alloc(sizeof(struct value_s));
        memset(added, 0, sizeof(struct value_s));
        hashtable[id] = added;
        added->subnet.value = s.value;
        return added;
    } else {
        while (v->next && v->subnet.value != s.value) v = v->next;
        if (v->subnet.value == s.value) return v;
        struct value_s *added = (struct value_s *)alloc(sizeof(struct value_s));
        memset(added, 0, sizeof(struct value_s));
        v->next = added;
        added->subnet.value = s.value;
        return added;
    }
}

void remove_route_from_peer(struct value_s *v, uint8 peer_id) {
    bool exists = false;
    float highest_pref = 0.0;
    uint8 highest_pref_peer = 0;
    struct rib_route_s *highest_pref_route;
    for (uint8 i = 0; i < v->route_count; ++i) {
        if (v->routes[i].peer_id == peer_id) {
            exists = true;
        } else if (v->routes[i].pref > highest_pref) {
            highest_pref = v->routes[i].pref;
            highest_pref_peer = v->routes[i].peer_id;
            highest_pref_route = &v->routes[i];
        }
    }
    if (!exists)
        return;
    --bgp.neighbors[peer_id].routes_count;
    if (v->route_count == 1) {
        --bgp.neighbors[peer_id].installed_routes_count;
        kernel_remove_route(v->subnet, v->routes[0].nexthop, bgp.neighbors[peer_id].if_index);
        free(v->routes);
        v->route_count = 0;
    } else {
        struct rib_route_s *new_routes = (struct rib_route_s *)alloc(sizeof(struct rib_route_s) * (v->route_count - 1));
        for (uint8 i = 0, y = 0; i < v->route_count; ++i) {
            if (v->routes[i].peer_id != peer_id) {
                memcpy(&new_routes[y], &v->routes[i], sizeof(struct rib_route_s));
                ++y;
            }
        }
        if (v->best_route_peer_id == peer_id) {
            kernel_update_route(v->subnet, highest_pref_route->nexthop, bgp.neighbors[highest_pref_route->peer_id].if_index);
            ++bgp.neighbors[highest_pref_peer].installed_routes_count;
            v->best_route_peer_id = highest_pref_peer;
        }
        free(v->routes);
        v->routes = new_routes;
        --v->route_count;
    }
}

void hashtable_remove_peer(uint8 peer_id) {
    uint32 s = 1000000;
    if (!bgp.has_non_default_route)
        s = 1;
    for (uint32 i = 0; i < s; ++i) {
        struct value_s *v = hashtable[i], **prev_next = &hashtable[i];
        while (v) {
            struct value_s *next = v->next;
            if (!(v->route_count == 1 && v->best_route_peer_id != peer_id))
                remove_route_from_peer(v, peer_id);
            if (v->route_count == 0) {
                free(v);
                (*prev_next) = next;
            } else
                prev_next = &v->next;
            v = next;
        }
    }
}

void hashtable_update_peer_id(uint8 peer_id_old, uint8 peer_id_new) {
    uint32 s = 1000000;
    if (!bgp.has_non_default_route)
        s = 1;
    for (uint32 i = 0; i < s; ++i) {
        struct value_s *v = hashtable[i];
        while (v) {
            if (v->best_route_peer_id == peer_id_old)
                v->best_route_peer_id = peer_id_new;
            for (uint8 i = 0; i < v->route_count; ++i) {
                struct rib_route_s *route = &v->routes[i];
                if (route->peer_id == peer_id_old)
                    route->peer_id = peer_id_new;
            }
            v = v->next;
        }
    }
}

void hashtable_remove_route(union rib_subnet_u s, uint8 peer_id) {
    uint32 id = get_hash(s);
    struct value_s *v = hashtable[id], **prev_next = &hashtable[id];
    if (v == NULL) return;
    while (v->next && v->subnet.value != s.value) prev_next = &v->next, v = v->next;
    if (v->subnet.value != s.value) return;
    remove_route_from_peer(v, peer_id);
    if (v->route_count == 0) {
        (*prev_next) = v->next;
        free(v);
    }
}

void hashtable_add_route(union rib_subnet_u s, uint8 peer_id, float pref, uint8 *nexthop) {
    struct value_s *v = hashtable_get_add(s);
    float highest_pref = 0.0;
    uint8 highest_pref_peer = 0;
    struct rib_route_s *existing_route = NULL, *highest_pref_route;
    for (uint8 i = 0; i < v->route_count; ++i) {
        if (v->routes[i].peer_id == peer_id) {
            existing_route = &v->routes[i];
        } else if (v->routes[i].pref > highest_pref) {
            highest_pref = v->routes[i].pref;
            highest_pref_peer = v->routes[i].peer_id;
            highest_pref_route = &v->routes[i];
        }
    }
    if (existing_route) {
        if (v->best_route_peer_id == peer_id) {
            if (pref < highest_pref) {
                kernel_update_route(s, highest_pref_route->nexthop, bgp.neighbors[highest_pref_route->peer_id].if_index);
                v->best_route_peer_id = highest_pref_peer;
                --bgp.neighbors[peer_id].installed_routes_count;
                ++bgp.neighbors[highest_pref_peer].installed_routes_count;
            } else {
                kernel_update_route(s, nexthop, bgp.neighbors[peer_id].if_index);
            }
        }
        existing_route->pref = pref;
        memcpy(existing_route->nexthop, nexthop, 16);
    } else {
        if (pref > highest_pref) {
            if (highest_pref)
                --bgp.neighbors[highest_pref_peer].installed_routes_count;
            ++bgp.neighbors[peer_id].installed_routes_count;
            v->best_route_peer_id = peer_id;
            kernel_update_route(s, nexthop, bgp.neighbors[peer_id].if_index);
        }
        ++v->route_count;
        v->routes = v->route_count > 1 ? (struct rib_route_s *)safe_realloc(v->routes, sizeof(struct rib_route_s) * v->route_count) : (struct rib_route_s *)alloc(sizeof(struct rib_route_s));
        v->routes[v->route_count - 1].peer_id = peer_id;
        v->routes[v->route_count - 1].pref = pref;
        memcpy(v->routes[v->route_count - 1].nexthop, nexthop, 16);
        ++bgp.neighbors[peer_id].routes_count;
    }
}
