#include "kernel_routing.h"

extern struct bgp_main_s bgp;

void kernel_clear_table(void) {
    struct PADDED {
        struct nlmsghdr hdr;
        struct rtmsg msg;
    } req;
    memset(&req, 0, sizeof(req));
    req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.hdr.nlmsg_type = RTM_GETROUTE;
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.msg.rtm_family = AF_INET6;
    req.msg.rtm_table = bgp.routing_table_id;
    send(bgp.netlink_fd, &req, req.hdr.nlmsg_len, 0);
    uint8 recvbuf[32768];
    int len;
    struct nlmsghdr *nlh;
    while ((len = recv(bgp.netlink_fd, &recvbuf, sizeof(recvbuf), 0)) > 0) {
        for (nlh = (struct nlmsghdr *)recvbuf; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
            if (nlh->nlmsg_type == NLMSG_DONE)
                return;
            if (nlh->nlmsg_type != RTM_NEWROUTE)
                continue;
            struct rtmsg *msg = NLMSG_DATA(nlh);
            if (msg->rtm_table != bgp.routing_table_id)
                continue;
            nlh->nlmsg_type = RTM_DELROUTE;
            nlh->nlmsg_flags = NLM_F_REQUEST;
            send(bgp.netlink_fd, nlh, nlh->nlmsg_len, 0);
        }
    }
}

static void netlink_attribute(struct nlmsghdr *hdr, int type, void *data, uint16 length) {
    uint16 rta_length = RTA_LENGTH(length);
    struct rtattr *rta;
    if (NLMSG_ALIGN(hdr->nlmsg_len) + RTA_ALIGN(rta_length) > sizeof(struct nlmsghdr)+ sizeof(struct rtmsg) + 4096)
        return;
    rta = (struct rtattr *)(((void *)hdr) + NLMSG_ALIGN(hdr->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len = rta_length;
    memcpy(RTA_DATA(rta), data, length);
    hdr->nlmsg_len = NLMSG_ALIGN(hdr->nlmsg_len) + RTA_ALIGN(rta_length);
}

static void kernel_route(union rib_subnet_u subnet, uint8 *nexthop, int if_index, int nlmsg_type, int nlmsg_flags) {
    struct PADDED {
        struct nlmsghdr hdr;
        struct rtmsg msg;
        uint8 attributes[4096];
    } req;
    memset(&req, 0, sizeof(req));
    req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.hdr.nlmsg_type = nlmsg_type;
    req.hdr.nlmsg_flags = nlmsg_flags;
    req.msg.rtm_family = AF_INET6;
    req.msg.rtm_table = bgp.routing_table_id;
    req.msg.rtm_scope = RT_SCOPE_UNIVERSE;
    req.msg.rtm_type = RTN_UNICAST;
    req.msg.rtm_dst_len = subnet.subnet.subnet_length;
    req.msg.rtm_protocol = RTPROT_STATIC;
    uint8 ipv6[16];
    memset(ipv6, 0, 16);
    memcpy(ipv6, subnet.subnet.ipv6, (subnet.subnet.subnet_length + 7) / 8);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Waddress-of-packed-member"

    netlink_attribute(&req.hdr, RTA_DST, ipv6, 16);
    netlink_attribute(&req.hdr, RTA_GATEWAY, nexthop, 16);
    netlink_attribute(&req.hdr, RTA_OIF, &if_index, sizeof(if_index));

#pragma GCC diagnostic pop

    send(bgp.netlink_fd, &req, req.hdr.nlmsg_len, 0);
}

void kernel_remove_route(union rib_subnet_u subnet, uint8 *nexthop, int if_index) {
    kernel_route(subnet, nexthop, if_index, RTM_DELROUTE, NLM_F_REQUEST);
}

void kernel_update_route(union rib_subnet_u subnet, uint8 *nexthop, int if_index) {
    kernel_route(subnet, nexthop, if_index, RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK);
    uint8 recvbuf[32768];
    recv(bgp.netlink_fd, &recvbuf, sizeof(recvbuf), 0);
}
