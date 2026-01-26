#ifndef INCLUDE_KERNEL_ROUTING
#define INCLUDE_KERNEL_ROUTING

#include "include.h"
#include "rib.h"
#include "bgp.h"

void kernel_clear_table(void);
void kernel_remove_route(union rib_subnet_u subnet, uint8 *nexthop, int if_index);
void kernel_update_route(union rib_subnet_u subnet, uint8 *nexthop, int if_index);

#endif
