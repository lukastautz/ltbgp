#include "bgp.h"

time_t now;

struct bgp_main_s bgp;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wbuiltin-declaration-mismatch"

void log(char *str0, char *str1, char *str2, char *str3) {
    uint16 lens[4] = {
        str0 ? strlen(str0) : 0,
        str1 ? strlen(str1) : 0,
        str2 ? strlen(str2) : 0,
        str3 ? strlen(str3) : 0
    };
    char buf[2048];
    struct tm *tm_info = localtime(&now);
    strftime(buf, sizeof(buf), "[%d.%m.%Y %H:%M:%S] ", tm_info);
    uint16 pos = strlen(buf);
    if (str0) {
        buf[pos++] = '[';
        memcpy(buf + pos, str0, lens[0]);
        pos += lens[0];
        buf[pos++] = ']';
        buf[pos++] = ' ';
    }
    if (str1) {
        memcpy(buf + pos, str1, lens[1]);
        pos += lens[1];
    }
    if (str2) {
        buf[pos++] = ';';
        buf[pos++] = ' ';
        memcpy(buf + pos, str2, lens[2]);
        pos += lens[2];
    }
    if (str3) {
        buf[pos++] = ' ';
        buf[pos++] = '(';
        memcpy(buf + pos, str3, lens[3]);
        pos += lens[3];
        buf[pos++] = ')';
    }
    buf[pos++] = '\n';
    write(bgp.log_fd, buf, pos);
}

#pragma GCC diagnostic pop

void *alloc(uint32 bytes) {
    if (bytes == 0) return NULL;
    void *result = malloc(bytes);
    if (result == NULL) {
        write(2, "Error: malloc() failed!", strlen("Error: malloc() failed!"));
        exit(99);
    }
    return result;
}

void *safe_realloc(void *ptr, uint32 bytes) {
    if (ptr == NULL) return alloc(bytes);
    void *result = realloc(ptr, bytes);
    if (result == NULL) {
        write(2, "Error: realloc() failed!", strlen("Error: realloc() failed!"));
        exit(99);
    }
    return result;
}

char *safe_strdup(char *str) {
    uint16 len = strlen(str);
    char *result = alloc(len + 1);
    memcpy(result, str, len);
    result[len] = '\0';
    return result;
}

void disconnect(struct bgp_neighbor_s *neighbor, char *str1, char *str2, char *str3) {
    neighbor->state = BGP_NEIGHBOR_DISCONNECTED;
    neighbor->disconnected_at = now;
    ++neighbor->failure_count;
    close(neighbor->tcp_fd);
    log(neighbor->name, str1, str2, str3);
    if (neighbor->routes_count) {
        hashtable_remove_peer(neighbor->id);
    }
}

void construct_update_withdraw_message(struct bgp_neighbor_s *neighbor) {
    uint16 total_length = 0;
    struct bgp_message_header_s *header = (struct bgp_message_header_s *)neighbor->send_buf;
    total_length += sizeof(struct bgp_message_header_s);
    header->type = BGP_TYPE_UPDATE;
    uint16 *withdrawn_routes_length = (uint16 *)(neighbor->send_buf + total_length);
    total_length += 2;
    *withdrawn_routes_length = __bswap_16(0);
    uint16 *total_path_attributes_length = (uint16 *)(neighbor->send_buf + total_length);
    total_length += 2;
    struct bgp_update_path_attribute_s *path_attribute_header = (struct bgp_update_path_attribute_s *)(neighbor->send_buf + total_length);
    path_attribute_header->flags = 0b10000000;
    path_attribute_header->typecode = BGP_UPDATE_TYPECODE_MP_UNREACH_NLRI;
    path_attribute_header->length = sizeof(struct bgp_update_mp_header_s) + neighbor->locally_withdrawn_routes_length;
    total_length += sizeof(struct bgp_update_path_attribute_s);
    struct bgp_update_mp_header_s *mp_unreach_nlri = (struct bgp_update_mp_header_s *)(neighbor->send_buf + total_length);
    mp_unreach_nlri->AFI = __bswap_16(AFI_IPV6);
    mp_unreach_nlri->SAFI = SAFI_UNICAST;
    total_length += sizeof(struct bgp_update_mp_header_s);
    memcpy(neighbor->send_buf + total_length, neighbor->locally_withdrawn_routes_raw, neighbor->locally_withdrawn_routes_length);
    total_length += neighbor->locally_withdrawn_routes_length;
    *total_path_attributes_length = __bswap_16(total_length - 4 - sizeof(struct bgp_message_header_s));
    header->length = __bswap_16(total_length);
    neighbor->total_bytes_to_send = total_length;
    neighbor->sent_bytes = 0;
    free(neighbor->locally_withdrawn_routes_raw);
    neighbor->locally_withdrawn_routes_length = 0;
}

void construct_update_message(struct bgp_neighbor_s *neighbor, struct bgp_main_s *bgp) {
    struct bgp_route_s *route = bgp->routes;
    uint16 routes_skipped = 0;
    while (routes_skipped < neighbor->local_routes_sent) {
        if (bgp->announcing_groups[route->bgp_announcing_group_id].announcement_specs[neighbor->id].announce)
            ++routes_skipped;
        ++route;
    }
    struct bgp_announcement_specs_s *announcement_specs = &bgp->announcing_groups[route->bgp_announcing_group_id].announcement_specs[neighbor->id];
    ++neighbor->local_routes_sent;
    uint16 total_length = 0;
    struct bgp_message_header_s *header = (struct bgp_message_header_s *)neighbor->send_buf;
    total_length += sizeof(struct bgp_message_header_s);
    header->type = BGP_TYPE_UPDATE;
    uint16 *withdrawn_routes_length = (uint16 *)(neighbor->send_buf + total_length);
    total_length += 2;
    *withdrawn_routes_length = __bswap_16(0);
    uint16 *total_path_attributes_length = (uint16 *)(neighbor->send_buf + total_length);
    total_length += 2;
    struct bgp_update_path_attribute_s *path_attribute_header = (struct bgp_update_path_attribute_s *)(neighbor->send_buf + total_length);
    total_length += sizeof(struct bgp_update_path_attribute_s);
    path_attribute_header->flags = 0b01000000;
    path_attribute_header->typecode = BGP_UPDATE_TYPECODE_ORIGIN;
    path_attribute_header->length = 1;
    uint8 *origin_attribute = (uint8 *)(neighbor->send_buf + total_length);
    total_length += 1;
    *origin_attribute = 2; // INCOMPLETE; neither learned over IGP nor EGP
    // NEXT_HOP is omitted as required by RFC 4760
    if (neighbor->supports_32bit) {
        // As required by RFC 6793, AS_PATH is used with 4-octet ASNs
        path_attribute_header = (struct bgp_update_path_attribute_s *)(neighbor->send_buf + total_length);
        path_attribute_header->flags = 0b01000000;
        path_attribute_header->typecode = BGP_UPDATE_TYPECODE_AS_PATH;
        path_attribute_header->length = 2 + 4 * (announcement_specs->prepend_n_times + 1);
        total_length += sizeof(struct bgp_update_path_attribute_s);
        uint8 *segment_type = (uint8 *)(neighbor->send_buf + total_length);
        *segment_type = 2; // AS_SEQUENCE;
        total_length += 1;
        uint8 *segment_length = (uint8 *)(neighbor->send_buf + total_length);
        total_length += 1;
        *segment_length = announcement_specs->prepend_n_times + 1;
        for (uint8 i = 0; i <= announcement_specs->prepend_n_times; ++i) {
            uint32 *as_path_pos = (uint32 *)(neighbor->send_buf + total_length + 4 * i);
            *as_path_pos = __bswap_32(bgp->local_asn_32bit);
        }
        total_length += 4 * (announcement_specs->prepend_n_times + 1);
    } else {
        path_attribute_header = (struct bgp_update_path_attribute_s *)(neighbor->send_buf + total_length);
        path_attribute_header->flags = 0b01000000;
        path_attribute_header->typecode = BGP_UPDATE_TYPECODE_AS_PATH;
        path_attribute_header->length = 2 + 2 * (announcement_specs->prepend_n_times + 1);
        total_length += sizeof(struct bgp_update_path_attribute_s);
        uint8 *segment_type = (uint8 *)(neighbor->send_buf + total_length);
        *segment_type = 2; // AS_SEQUENCE;
        total_length += 1;
        uint8 *segment_length = (uint8 *)(neighbor->send_buf + total_length);
        total_length += 1;
        *segment_length = announcement_specs->prepend_n_times + 1;
        for (uint8 i = 0; i <= announcement_specs->prepend_n_times; ++i) {
            uint16 *as_path_pos = (uint16 *)(neighbor->send_buf + total_length + 2 * i);
            *as_path_pos = __bswap_16(bgp->local_asn);
        }
        total_length += 2 * (announcement_specs->prepend_n_times + 1);
        path_attribute_header = (struct bgp_update_path_attribute_s *)(neighbor->send_buf + total_length);
        path_attribute_header->flags = 0b11000000;
        path_attribute_header->typecode = BGP_UPDATE_TYPECODE_AS4_PATH;
        path_attribute_header->length = 2 + 4 * (announcement_specs->prepend_n_times + 1);
        total_length += sizeof(struct bgp_update_path_attribute_s);
        segment_type = (uint8 *)(neighbor->send_buf + total_length);
        *segment_type = 2; // AS_SEQUENCE;
        total_length += 1;
        segment_length = (uint8 *)(neighbor->send_buf + total_length);
        total_length += 1;
        *segment_length = announcement_specs->prepend_n_times + 1;
        for (uint8 i = 0; i <= announcement_specs->prepend_n_times; ++i) {
            uint32 *as_path_pos = (uint32 *)(neighbor->send_buf + total_length + 4 * i);
            *as_path_pos = __bswap_32(bgp->local_asn_32bit);
        }
        total_length += 4 * (announcement_specs->prepend_n_times + 1);
    }
    if (announcement_specs->communities_count) {
        path_attribute_header = (struct bgp_update_path_attribute_s *)(neighbor->send_buf + total_length);
        path_attribute_header->flags = 0b11000000;
        path_attribute_header->typecode = BGP_UPDATE_TYPECODE_COMMUNITIES;
        path_attribute_header->length = 4 * announcement_specs->communities_count;
        total_length += sizeof(struct bgp_update_path_attribute_s);
        for (uint8 i = 0; i < announcement_specs->communities_count; ++i) {
            uint16 *community = (uint16 *)&announcement_specs->communities[i];
            uint16 *buf = (uint16 *)(neighbor->send_buf + total_length + 4 * i);
            *buf = __bswap_16(*community);
            ++buf, ++community;
            *buf = __bswap_16(*community);
        }
        total_length += 4 * announcement_specs->communities_count;
    }
    if (announcement_specs->large_communities_count) {
        path_attribute_header = (struct bgp_update_path_attribute_s *)(neighbor->send_buf + total_length);
        path_attribute_header->flags = 0b11000000;
        path_attribute_header->typecode = BGP_UPDATE_TYPECODE_LARGE_COMMUNITIES;
        path_attribute_header->length = 12 * announcement_specs->large_communities_count;
        total_length += sizeof(struct bgp_update_path_attribute_s);
        for (uint8 i = 0; i < announcement_specs->large_communities_count; ++i) {
            uint32 *parts = &announcement_specs->large_communities[i * 3];
            uint32 *buf = (uint32 *)(neighbor->send_buf + total_length + 12 * i);
            *buf = __bswap_32(parts[0]);
            ++buf;
            *buf = __bswap_32(parts[1]);
            ++buf;
            *buf = __bswap_32(parts[2]);
        }
        total_length += 12 * announcement_specs->large_communities_count;
    }
    path_attribute_header = (struct bgp_update_path_attribute_s *)(neighbor->send_buf + total_length);
    path_attribute_header->flags = 0b10000000;
    path_attribute_header->typecode = BGP_UPDATE_TYPECODE_MP_REACH_NLRI;
    path_attribute_header->length = sizeof(struct bgp_update_mp_reach_nrli_ipv6_s) + 1 + (route->prefix_length + 7) / 8;
    total_length += sizeof(struct bgp_update_path_attribute_s);
    struct bgp_update_mp_reach_nrli_ipv6_s *mp_reach_nlri = (struct bgp_update_mp_reach_nrli_ipv6_s *)(neighbor->send_buf + total_length);
    mp_reach_nlri->AFI = __bswap_16(AFI_IPV6);
    mp_reach_nlri->SAFI = SAFI_UNICAST;
    mp_reach_nlri->next_hop_length = 16;
    memcpy(&mp_reach_nlri->next_hop, neighbor->local_ip, 16);
    mp_reach_nlri->res = 0;
    total_length += sizeof(struct bgp_update_mp_reach_nrli_ipv6_s);
    uint8 *prefix_length = (uint8 *)(neighbor->send_buf + total_length);
    *prefix_length = route->prefix_length;
    total_length += 1;
    memcpy(neighbor->send_buf + total_length, route->prefix, (route->prefix_length + 7) / 8);
    total_length += (route->prefix_length + 7) / 8;
    *total_path_attributes_length = __bswap_16(total_length - 4 - sizeof(struct bgp_message_header_s));
    header->length = __bswap_16(total_length);
    neighbor->total_bytes_to_send = total_length;
    neighbor->sent_bytes = 0;
}

#define HANDLE_ERROR(func, descr) \
    if (func == -1) { \
        disconnect(neighbor, "Error at " descr, NULL, NULL); \
        return; \
    }

void handle_neighbor(uint16 id) {
    struct bgp_neighbor_s *neighbor = &bgp.neighbors[id];
    switch (neighbor->state) {
        case BGP_NEIGHBOR_FAILED:
            return;
        case BGP_NEIGHBOR_DISCONNECTED:
            if (neighbor->failure_count >= 50) {
                neighbor->state = BGP_NEIGHBOR_FAILED;
                log(neighbor->name, "Connection to neighbor marked as failed due to 50 failed connection attempts", NULL, NULL);
                return;
            }
            uint8 retry_after_n_seconds = neighbor->failure_count * 5;
            if (neighbor->disconnected_at + retry_after_n_seconds < now) {
                neighbor->local_routes_sent = 0;
                neighbor->routes_count = 0;
                neighbor->tcp_fd = socket(AF_INET6, SOCK_STREAM, 0);
                neighbor->last_keepalive_received = now;
                neighbor->recv_bytes = 0;
                neighbor->received_open = false;
                neighbor->connected_at = 0;
                neighbor->disconnected_at = 0;
                HANDLE_ERROR(neighbor->tcp_fd, "socket")
                int flags = fcntl(neighbor->tcp_fd, F_GETFL, 0);
                HANDLE_ERROR(fcntl(neighbor->tcp_fd, F_SETFL, flags | O_NONBLOCK), "fcntl")
                HANDLE_ERROR(setsockopt(neighbor->tcp_fd, SOL_SOCKET, SO_BINDTODEVICE, neighbor->if_name, strlen(neighbor->if_name)), "setsockopt")
                struct sockaddr_in6 local, remote;
                memset(&local, 0, sizeof(local));
                memset(&remote, 0, sizeof(remote));
                memcpy(&local.sin6_addr, neighbor->local_ip, 16);
                memcpy(&remote.sin6_addr, neighbor->remote_ip, 16);
                local.sin6_family = remote.sin6_family = AF_INET6;
                remote.sin6_port = htons(179);
                HANDLE_ERROR(bind(neighbor->tcp_fd, (struct sockaddr *)&local, sizeof(local)), "bind")
                if (neighbor->md5_password) {
                    struct tcp_md5sig md5sig;
                    memset(&md5sig, 0, sizeof(md5sig));
                    md5sig.tcpm_keylen = neighbor->md5_password_length;
                    memcpy(md5sig.tcpm_key, neighbor->md5_password, neighbor->md5_password_length);
                    memcpy(&md5sig.tcpm_addr, &remote, sizeof(remote));
                    HANDLE_ERROR(setsockopt(neighbor->tcp_fd, IPPROTO_TCP, TCP_MD5SIG, &md5sig, sizeof(md5sig)), "setsockopt md5")
                }
                int ttl = neighbor->multihop;
                HANDLE_ERROR(setsockopt(neighbor->tcp_fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl)), "setsockopt IPV6_UNICAST_HOPS")
                int res;
connect:
                res = connect(neighbor->tcp_fd, (struct sockaddr *)&remote, sizeof(remote));
                if (res == -1 && errno != EINPROGRESS) {
                    if (errno == EINTR)
                        goto connect;
                    close(neighbor->tcp_fd);
                    log(neighbor->name, "Error while attempting to connect()", NULL, NULL);
                    neighbor->state = BGP_NEIGHBOR_FAILED;
                } else {
                    neighbor->state = BGP_NEIGHBOR_CONNECTING;
                }
            } else {
            }
            return;
        case BGP_NEIGHBOR_CONNECTING: {
            struct pollfd pollreq = {
                .fd = neighbor->tcp_fd,
                .events = POLLOUT
            };
            int res = poll(&pollreq, 1, 0);
            if (res == 0 || (res == -1 && errno == EINTR))
                return;
            if (res == -1) {
                disconnect(neighbor, "poll() failed", strerror(errno), NULL);
                return;
            }
            int err;
            socklen_t len = sizeof(err);
            getsockopt(neighbor->tcp_fd, SOL_SOCKET, SO_ERROR, &err, &len);
            if (err != 0) {
                disconnect(neighbor, "connect() failed", strerror(err), NULL);
                return;
            }
            log(neighbor->name, "Connected to remote host, sending OPEN message", NULL, NULL);
            struct bgp_message_header_s *header = (struct bgp_message_header_s *)neighbor->send_buf;
            header->type = BGP_TYPE_OPEN;
            header->length = __bswap_16(sizeof(struct bgp_message_header_s) + sizeof(struct bgp_open_header_s) + sizeof(struct bgp_open_optional_parameter_header_s) + sizeof(struct bgp_capability_header_s) * 2 + sizeof(struct bgp_capability_multiprotocol_s) + 4);
            struct bgp_open_header_s *open_header = (struct bgp_open_header_s *)((void *)header + sizeof(*header));
            open_header->version = 4;
            open_header->asn = __bswap_16(bgp.local_asn);
            open_header->hold_time = __bswap_16(neighbor->hold_time);
            open_header->identifier = bgp.identifier;
            open_header->optional_parameter_length = sizeof(struct bgp_open_optional_parameter_header_s) + sizeof(struct bgp_capability_header_s) * 2 + sizeof(struct bgp_capability_multiprotocol_s) + 4;
            struct bgp_open_optional_parameter_header_s *optional_parameter_header = (struct bgp_open_optional_parameter_header_s *)((void *)open_header + sizeof(*open_header));
            optional_parameter_header->type = BGP_OPEN_OPTIONAL_PARAMETER_CAPABILITIES;
            optional_parameter_header->data_length = sizeof(struct bgp_capability_header_s) * 2 + sizeof(struct bgp_capability_multiprotocol_s) + 4;
            struct bgp_capability_header_s *capability_header_multiprotocol = (struct bgp_capability_header_s *)((void *)optional_parameter_header + sizeof(*optional_parameter_header));
            capability_header_multiprotocol->code = BGP_CAPABILITY_CODE_MULTIPROTOCOL_EXTENSIONS;
            capability_header_multiprotocol->data_length = sizeof(struct bgp_capability_multiprotocol_s);
            struct bgp_capability_multiprotocol_s *capability_multiprotocol = (struct bgp_capability_multiprotocol_s *)((void *)capability_header_multiprotocol + sizeof(*capability_header_multiprotocol));
            capability_multiprotocol->AFI = __bswap_16(AFI_IPV6);
            capability_multiprotocol->res = 0;
            capability_multiprotocol->SAFI = SAFI_UNICAST;
            struct bgp_capability_header_s *capability_header_32bit_asns = (struct bgp_capability_header_s *)((void *)capability_multiprotocol + sizeof(*capability_multiprotocol));
            capability_header_32bit_asns->code = BGP_CAPABILITY_CODE_4_OCTET_ASNS;
            capability_header_32bit_asns->data_length = 4;
            uint32 *capability_32bit_asns = (uint32 *)((void *)capability_header_32bit_asns + sizeof(*capability_header_32bit_asns));
            *capability_32bit_asns = __bswap_32(bgp.local_asn_32bit);
            neighbor->total_bytes_to_send = __bswap_16(header->length);
            neighbor->sent_bytes = 0;
            neighbor->state = BGP_NEIGHBOR_SENDING_OPEN;
            neighbor->connected_at = now;
            neighbor->last_keepalive_sent = now;
            neighbor->local_routes_sent = 0;
            neighbor->routes_count = 0;
            neighbor->installed_routes_count = 0;
            neighbor->time_started_sending = now;
            return;
        }
        case BGP_NEIGHBOR_SENDING_UPDATE:
        case BGP_NEIGHBOR_SENDING_KEEPALIVE:
        case BGP_NEIGHBOR_SENDING_OPEN:
        case BGP_NEIGHBOR_SENDING_NOTIFICATION: {
            int sent = write(neighbor->tcp_fd, neighbor->send_buf + neighbor->sent_bytes, neighbor->total_bytes_to_send - neighbor->sent_bytes);
            if (sent == -1) {
                if (errno != EAGAIN && errno != EINTR && errno != EWOULDBLOCK) {
                    disconnect(neighbor, "Writing to TCP connection failed", strerror(errno), NULL);
                }
                return;
            }
            neighbor->sent_bytes += sent;
            if (neighbor->sent_bytes == neighbor->total_bytes_to_send) {
                if (neighbor->state == BGP_NEIGHBOR_SENDING_NOTIFICATION) {
                    disconnect(neighbor, "Closing connection after sending a BGP NOTIFICATION message", NULL, NULL);
                } else {
                    if (neighbor->state != BGP_NEIGHBOR_SENDING_OPEN && neighbor->locally_withdrawn_routes_length != 0) {
                        construct_update_withdraw_message(neighbor);
                        neighbor->state = BGP_NEIGHBOR_SENDING_UPDATE;
                        neighbor->time_started_sending = now;
                    } else if (neighbor->state != BGP_NEIGHBOR_SENDING_OPEN && neighbor->local_routes_sent != neighbor->local_routes_total) {
                        construct_update_message(neighbor, &bgp);
                        neighbor->state = BGP_NEIGHBOR_SENDING_UPDATE;
                        neighbor->time_started_sending = now;
                    } else if (neighbor->state == BGP_NEIGHBOR_SENDING_UPDATE) {
                        neighbor->state = BGP_NEIGHBOR_CONNECTED;
                        log(neighbor->name, "All routes were sent", NULL, NULL);
                    } else {
                        neighbor->state = BGP_NEIGHBOR_CONNECTED;
                    }
                } 
            } else {
                if (neighbor->time_started_sending + 30 <= now) {
                    // should prevent https://blog.benjojo.co.uk/post/bgp-stuck-routes-tcp-zero-window
                    disconnect(neighbor, "Closing TCP connection due to failure to send message", NULL, NULL);
                }
            }
            return;
        }
        case BGP_NEIGHBOR_CONNECTED: {
            int received = read(neighbor->tcp_fd, neighbor->recv_buf + neighbor->recv_bytes, sizeof(neighbor->recv_buf) - neighbor->recv_bytes);
            if (received == -1) {
                if (errno != EAGAIN && errno != EINTR && errno != EWOULDBLOCK) {
                    disconnect(neighbor, "Reading from TCP connection failed", strerror(errno), NULL);
                }
                if (neighbor->received_open && neighbor->last_keepalive_received + neighbor->used_hold_time + 5 <= now) {
                    disconnect(neighbor, "Hold timer expired", NULL, NULL);
                    return;
                }
                return;
            }
            if (received == 0) {
                disconnect(neighbor, "TCP connection was terminated by neighbor", NULL, NULL);
                return;
            }
            neighbor->recv_bytes += received;
validate:
            validate_bgp_message(neighbor->recv_buf, neighbor->recv_bytes, &neighbor->validator);
            switch (neighbor->validator.state) {
                case BGP_MESSAGE_INCOMPLETE:
                    if (!neighbor->received_open && neighbor->connected_at + 30 < now) {
                        disconnect(neighbor, "Did not receive a BGP OPEN message within 30 seconds, closing connection", NULL, NULL);
                        return;
                    }
                    break;
                case BGP_MESSAGE_CONNECTION_CLOSED:
                    disconnect(neighbor, "Connection closed by neighbor", neighbor->validator.error_str, neighbor->validator.suberror_str);
                    return;
                case BGP_MESSAGE_INVALID: {
                    log(neighbor->name, "Sending NOTIFICATION due to invalid message", neighbor->validator.error_str, neighbor->validator.suberror_str);
                    struct bgp_message_header_s *header = (struct bgp_message_header_s *)neighbor->send_buf;
                    header->type = BGP_TYPE_NOTIFICATION;
                    header->length = __bswap_16(sizeof(struct bgp_message_header_s) + sizeof(struct bgp_notification_header_s));
                    struct bgp_notification_header_s *notification_header = (struct bgp_notification_header_s *)((void *)header + sizeof(*header));
                    notification_header->error = neighbor->validator.error;
                    notification_header->suberror = neighbor->validator.suberror;
                    neighbor->total_bytes_to_send = sizeof(struct bgp_message_header_s) + sizeof(struct bgp_notification_header_s);
                    neighbor->sent_bytes = 0;
                    neighbor->state = BGP_NEIGHBOR_SENDING_NOTIFICATION;
                    neighbor->time_started_sending = now;
                    return;
                }
                case BGP_MESSAGE_VALID:
                case BGP_MESSAGE_VALID_SUPPORTS_32BIT_ASNS:
                    neighbor->last_keepalive_received = now;
                    struct bgp_message_header_s *header = (struct bgp_message_header_s *)neighbor->recv_buf;
                    switch (header->type) {
                        case BGP_TYPE_KEEPALIVE:
                            break;
                        case BGP_TYPE_OPEN:
                            if (neighbor->received_open) {
                                disconnect(neighbor, "Received a second BGP OPEN message, closing connection", NULL, NULL);
                                return;
                            }
                            struct bgp_open_header_s *open_header = (struct bgp_open_header_s *)(neighbor->recv_buf + sizeof(struct bgp_message_header_s));
                            uint16 remote_hold_time = __bswap_16(open_header->hold_time);
                            neighbor->used_hold_time = remote_hold_time < neighbor->hold_time ? remote_hold_time : neighbor->hold_time;
                            neighbor->received_open = true;
                            neighbor->supports_32bit = neighbor->validator.state == BGP_MESSAGE_VALID_SUPPORTS_32BIT_ASNS;
                            log(neighbor->name, "Received valid OPEN message from neighbor", neighbor->supports_32bit ? "Neighbor supports 4-octet ASNs" : "Neighbor doesn't support 4-octet ASNs", NULL);
                            neighbor->last_keepalive_sent = 0; // send KEEPALIVE
                            break;
                        case BGP_TYPE_UPDATE:
                            if (neighbor->failure_count) neighbor->failure_count = 0;
                            if (neighbor->only_default_route) {
                                if (neighbor->routes_count == 0) {
                                    union rib_subnet_u subnet;
                                    memset(&subnet, 0, sizeof(subnet));
                                    hashtable_add_route(subnet, neighbor->id, (float)neighbor->localpref, neighbor->multihop > 1 ? neighbor->gateway : neighbor->remote_ip);
                                }
                                break;
                            }
                            if (neighbor->routelimit && neighbor->routes_count > neighbor->routelimit) {
                                disconnect(neighbor, "Disconnecting due to exceeding route limit", NULL, NULL);
                                return;
                            }
                            uint16 withdrawn_routes_length = *(uint16 *)((void *)header + sizeof(struct bgp_message_header_s));
                            withdrawn_routes_length = __bswap_16(withdrawn_routes_length);
                            uint16 path_attributes_length = *(uint16 *)((void *)header + sizeof(struct bgp_message_header_s) + 2 + withdrawn_routes_length);
                            path_attributes_length = __bswap_16(path_attributes_length);
                            uint16 path_attributes_start = withdrawn_routes_length + sizeof(struct bgp_message_header_s) + 4;
                            uint16 parsed_length = 0;
                            uint8 as_path_length = 0;
                            while ((parsed_length + 3) <= path_attributes_length) {
                                void *pos = (void *)header + path_attributes_start + parsed_length;
                                uint8 attribute_flags = *(uint8 *)pos;
                                uint8 attribute_type_code = *(uint8 *)(pos + 1);
                                uint16 length = *(uint8 *)(pos + 2);
                                if ((attribute_flags >> 4) & 1) { // extended length
                                    length = *(uint16 *)(pos + 2);
                                    length = __bswap_16(length);
                                    ++parsed_length;
                                    ++pos;
                                }
                                pos += 3;
                                parsed_length += 3 + length;
                                switch (attribute_type_code) {
                                    case BGP_UPDATE_TYPECODE_AS_PATH: {
                                        uint8 *as_path_len = (uint8 *)(pos + 1);
                                        if (*as_path_len > as_path_length)
                                            as_path_length = *as_path_len;
                                        break;
                                    }
                                }
                            }
                            if (!as_path_length)
                                as_path_length = 1;
                            float pref = (float)neighbor->localpref / (float)as_path_length;
                            if (neighbor->localpref == 0) pref = 1.0;
                            uint8 *next_hop;
                            parsed_length = 0;
                            while ((parsed_length + 3) <= path_attributes_length) {
                                void *pos = (void *)header + path_attributes_start + parsed_length;
                                uint8 attribute_flags = *(uint8 *)pos;
                                uint8 attribute_type_code = *(uint8 *)(pos + 1);
                                uint16 length = *(uint8 *)(pos + 2);
                                if ((attribute_flags >> 4) & 1) { // extended length
                                    length = *(uint16 *)(pos + 2);
                                    length = __bswap_16(length);
                                    ++parsed_length;
                                    ++pos;
                                }
                                pos += 3;
                                parsed_length += 3 + length;
                                switch (attribute_type_code) {
                                    case BGP_UPDATE_TYPECODE_MP_REACH_NLRI:
                                    case BGP_UPDATE_TYPECODE_MP_UNREACH_NLRI: {
                                        struct bgp_update_mp_header_s *mp_header = (struct bgp_update_mp_header_s *)pos;
                                        if (__bswap_16(mp_header->AFI) == AFI_IPV6 && mp_header->SAFI == SAFI_UNICAST) {
                                            if (attribute_type_code == BGP_UPDATE_TYPECODE_MP_REACH_NLRI) {
                                                uint8 next_hop_length = *(uint8 *)(pos + sizeof(struct bgp_update_mp_header_s));
                                                next_hop = (uint8 *)(pos + sizeof(struct bgp_update_mp_header_s) + 1);
                                                length -= 2 + next_hop_length, pos += 2 + next_hop_length; // next hop length (1 octet) + next hop + reserved (1 octet)
                                            }
                                            // check NLRI
                                            length -= sizeof(struct bgp_update_mp_header_s), pos += sizeof(struct bgp_update_mp_header_s);
                                            uint16 parsed_nlri_length = 0;
                                            while ((parsed_nlri_length + 1) <= length) {
                                                uint8 prefix_length = *(uint8 *)pos;
                                                ++pos;
                                                uint8 byte_length = (prefix_length + 7) / 8;
                                                if (prefix_length <= 48) {
                                                    union rib_subnet_u subnet;
                                                    subnet.subnet.subnet_length = prefix_length;
                                                    memcpy(subnet.subnet.ipv6, pos, byte_length);
                                                    subnet.value &= (0xFFULL | (((1ULL << prefix_length) - 1) << 8));
                                                    if (attribute_type_code == BGP_UPDATE_TYPECODE_MP_REACH_NLRI) {
                                                        hashtable_add_route(subnet, neighbor->id, pref, neighbor->multihop > 1 ? neighbor->gateway : next_hop);
                                                    } else {
                                                        hashtable_remove_route(subnet, neighbor->id);
                                                    }
                                                }
                                                pos += byte_length;
                                                parsed_nlri_length += byte_length + 1;
                                            }
                                        }
                                        break;
                                    }
                                }
                            }
                            break;
                    }
                    uint16 message_length = __bswap_16(header->length);
                    if (message_length < neighbor->recv_bytes) {
                        memmove(neighbor->recv_buf, neighbor->recv_buf + message_length, neighbor->recv_bytes - message_length);
                        neighbor->recv_bytes -= message_length;
                        goto validate;
                    } else {
                        neighbor->recv_bytes = 0;
                    }
            }
            if (neighbor->received_open && neighbor->last_keepalive_received + neighbor->used_hold_time + 5 <= now) {
                disconnect(neighbor, "Hold timer expired", NULL, NULL);
                return;
            }
            if (neighbor->received_open && neighbor->last_keepalive_sent + (neighbor->used_hold_time / 3) <= now) {
                struct bgp_message_header_s *header = (struct bgp_message_header_s *)neighbor->send_buf;
                header->length = __bswap_16(sizeof(struct bgp_message_header_s));
                header->type = BGP_TYPE_KEEPALIVE;
                neighbor->sent_bytes = 0;
                neighbor->total_bytes_to_send = sizeof(struct bgp_message_header_s);
                neighbor->state = BGP_NEIGHBOR_SENDING_KEEPALIVE;
                neighbor->time_started_sending = now;
                neighbor->last_keepalive_sent = now;
            }
            break;
        }
    }
}

void parse_settings(pid_t *read_pid, struct bgp_main_s *bgp);
void free_settings(struct bgp_main_s *bgp);

volatile sig_atomic_t send_status_flag = false;
volatile sig_atomic_t reload_config_flag = false;

void handle_sigusr1() {
    send_status_flag = true;
}

void handle_sighup() {
    reload_config_flag = true;
}

char status_send_buf[4096];
uint16 status_send_len = 0;

uint8 ltoa(uint32 n, char *s) {
    uint8 i = 0, y = 0, z;
    do
        s[i] = n % 10 + '0', ++i;
    while ((n /= 10) > 0);
    z = i - 1;
    for (char c; y < z; ++y, --z)
        c = s[y], s[y] = s[z], s[z] = c;
    return i;
}

bool send_int(int fd, uint32 i) {
    char buf[32];
    buf[ltoa(i, buf)] = '\0';
    uint8 len = strlen(buf);
    if (len + status_send_len > sizeof(status_send_buf)) {
        uint16 written = 0;
        int tmp;
        while (written < status_send_len && (tmp = write(fd, status_send_buf + written, status_send_len - written)) > 0)
            written += tmp;
        if (written != status_send_len) {
            return false;
        }
        status_send_len = 0;
    }
    memcpy(status_send_buf + status_send_len, buf, len);
    status_send_len += len;
    return true;
}

bool send_str(int fd, char *str, uint8 len) {
    if (len + status_send_len > sizeof(status_send_buf)) {
        uint16 written = 0;
        int tmp;
        while (written < status_send_len && (tmp = write(fd, status_send_buf + written, status_send_len - written)) > 0)
            written += tmp;
        if (written != status_send_len) {
            return false;
        }
        status_send_len = 0;
    }
    memcpy(status_send_buf + status_send_len, str, len);
    status_send_len += len;
    return true;
}

bool send_ip(int fd, uint8 *ip, uint8 ip_len, int type) {
    char buf[INET6_ADDRSTRLEN + 1];
    uint8 ipv46[16];
    memset(ipv46, 0, 16);
    memcpy(ipv46, ip, ip_len);
    if (!inet_ntop(type, ipv46, buf, sizeof(buf))) return false;
    return send_str(fd, buf, strlen(buf));
}

#define INT(i) if (!send_int(fd, i)) goto close;
#define STR(s) if (!send_str(fd, s, strlen(s))) goto close;
#define IP(ip, len, type) if (!send_ip(fd, ip, len, type)) goto close;

void send_status(void) {
    status_send_len = 0;
    if (!bgp.status_port)
        return;
    int fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd == -1)
        return;
    struct sockaddr_in6 dest;
    memset(&dest, 0, sizeof(dest));
    uint8 ipv6[16];
    inet_pton(AF_INET6, "::1", ipv6);
    memcpy(&dest.sin6_addr, ipv6, 16);
    dest.sin6_family = AF_INET6;
    dest.sin6_port = htons(bgp.status_port);
    if (connect(fd, (struct sockaddr *)&dest, sizeof(dest)) != 0) {
close:
        close(fd);
        return;
    }
    STR("Local ASN: ")
    INT(bgp.local_asn_32bit)
    STR("\n")
    STR("Routing table ID: ")
    INT(bgp.routing_table_id);
    STR("\n")
    STR("BGP identifier: ")
    IP((uint8 *)&bgp.identifier, 4, AF_INET)
    STR("\n\n")
    STR("Neighbors:")
    for (uint8 i = 0; i < bgp.neighbor_count; ++i) {
        struct bgp_neighbor_s *neighbor = &bgp.neighbors[i];
        STR("\n\tNeighbor ")
        STR(neighbor->name);
        STR("\n\t\tRemote ASN: ")
        INT(neighbor->remote_asn_32bit)
        STR("\n\t\tState: ")
        switch (neighbor->state) {
            case BGP_NEIGHBOR_FAILED: {
                char buf[2048];
                struct tm *tm_info = localtime(&neighbor->disconnected_at);
                strftime(buf, sizeof(buf), "Failed (since %d.%m.%Y %H:%M:%S)", tm_info);
                STR(buf)
                break;
            }
            case BGP_NEIGHBOR_DISCONNECTED: {
                if (neighbor->disconnected_at) {
                    char buf[2048];
                    struct tm *tm_info = localtime(&neighbor->disconnected_at);
                    strftime(buf, sizeof(buf), "Disconnected (since %d.%m.%Y %H:%M:%S)", tm_info);
                    STR(buf)
                } else {
                    STR("Disconnected")
                }
                break;
            }
            case BGP_NEIGHBOR_CONNECTED: {
                char buf[2048];
                struct tm *tm_info = localtime(&neighbor->connected_at);
                strftime(buf, sizeof(buf), "Established (since %d.%m.%Y %H:%M:%S)", tm_info);
                STR(buf)
                break;
            }
            case BGP_NEIGHBOR_CONNECTING: STR("Connecting") break;
            default: STR("Sending") break;
        }
        STR("\n\t\t")
        if (neighbor->routelimit) {
            STR("Routelimit: ")
            INT(neighbor->routelimit)
            STR("\n\t\t")
        }
        STR("Localpref: ")
        INT(neighbor->localpref)
        STR("\n\t\tInterface: ")
        STR(neighbor->if_name)
        STR("\n\t\tLocal IP: ")
        IP(neighbor->local_ip, 16, AF_INET6)
        STR("\n\t\tRemote IP: ")
        IP(neighbor->remote_ip, 16, AF_INET6)
        if (neighbor->multihop > 1) {
            STR("\n\t\tMultihop: ")
            INT(neighbor->multihop)
            STR("\n\t\tGateway: ")
            IP(neighbor->gateway, 16, AF_INET6)
        }
        if (neighbor->only_default_route) {
            STR("\n\t\tOnly default route")
        }
        if (neighbor->md5_password) {
            STR("\n\t\tMD5 password authentication enabled")
        }
        if (neighbor->state == BGP_NEIGHBOR_CONNECTED || neighbor->state <= 4) {
            STR("\n\t\tHold time: ")
            INT(neighbor->used_hold_time)
            STR(" (config: ")
            INT(neighbor->hold_time)
            STR(")")
        }
        STR("\n\t\tLocal routes: ")
        INT(neighbor->local_routes_total)
        if (neighbor->state == BGP_NEIGHBOR_CONNECTED || neighbor->state <= 4) {
            STR("\n\t\tReceived routes: ")
            INT(neighbor->routes_count)
            STR(" (")
            INT(neighbor->installed_routes_count)
            STR(" installed)")
        }
    }
    STR("\n\nGroups:")
    for (uint16 i = 0; i < bgp.announcing_group_count; ++i) {
        struct bgp_announcing_group_s *group = &bgp.announcing_groups[i];
        STR("\n\tGroup ")
        STR(group->name)
        for (uint8 y = 0; y < bgp.neighbor_count; ++y) {
            struct bgp_announcement_specs_s *specs = &group->announcement_specs[y];
            if (specs->announce) {
                STR("\n\t\tNeighbor ")
                STR(bgp.neighbors[y].name)
                if (specs->prepend_n_times) {
                    STR("\n\t\t\tPrepends: ")
                    INT(specs->prepend_n_times)
                }
                if (specs->communities_count) {
                    STR("\n\t\t\tCommunities:")
                    for (uint8 x = 0; x < specs->communities_count; ++x) {
                        uint16 *parts = (uint16 *)((void *)specs->communities + 4 * x);
                        STR(" ")
                        INT(*parts);
                        STR(":")
                        ++parts;
                        INT(*parts)
                    }
                }
                if (specs->large_communities_count) {
                    STR("\n\t\t\tLarge communities:")
                    for (uint8 x = 0; x < specs->large_communities_count; ++x) {
                        uint32 *parts = (uint32 *)((void *)specs->large_communities + 12 * x);
                        STR(" ")
                        INT(*parts);
                        STR(":")
                        ++parts;
                        INT(*parts)
                        STR(":")
                        ++parts;
                        INT(*parts)
                    }
                }
            }
        }
    }
    STR("\n\nRoutes:")
    for (uint16 i = 0; i < bgp.route_count; ++i) {
        struct bgp_route_s *route = &bgp.routes[i];
        STR("\n\tRoute ")
        IP(route->prefix, (route->prefix_length + 7) / 8, AF_INET6);
        STR("/")
        INT(route->prefix_length)
        STR(" ")
        STR(bgp.announcing_groups[route->bgp_announcing_group_id].name)
    }
    STR("\n")
    uint16 written = 0;
    int tmp;
    while (written < status_send_len && (tmp = write(fd, status_send_buf + written, status_send_len - written)) > 0)
        written += tmp;
    close(fd);
}

void reload_config(void) {
    log("MAIN", "Reloading configuration", NULL, NULL);
    close(bgp.log_fd);
    int netlink_fd = bgp.netlink_fd;
    struct bgp_main_s new_config;
    parse_settings(NULL, &new_config);
    new_config.netlink_fd = netlink_fd;
    if (new_config.local_asn_32bit != bgp.local_asn_32bit || new_config.routing_table_id != bgp.routing_table_id) {
        for (uint8 i = 0; i < bgp.neighbor_count; ++i) {
            if (bgp.neighbors[i].state != BGP_NEIGHBOR_DISCONNECTED && bgp.neighbors[i].state != BGP_NEIGHBOR_FAILED)
                close(bgp.neighbors[i].tcp_fd);
        }
        kernel_clear_table();
    } else {
        for (uint8 i = 0; i < bgp.neighbor_count; ++i) {
            struct bgp_neighbor_s *neighbor = &bgp.neighbors[i];
            if (neighbor->state != BGP_NEIGHBOR_DISCONNECTED && neighbor->state != BGP_NEIGHBOR_FAILED) {
                struct bgp_neighbor_s *new_neighbor = NULL;
                uint8 name_len = strlen(neighbor->name);
                for (uint8 i = 0; i < new_config.neighbor_count; ++i) {
                    if (strlen(new_config.neighbors[i].name) == name_len && !memcmp(new_config.neighbors[i].name, neighbor->name, name_len)) {
                        new_neighbor = &new_config.neighbors[i];
                        break;
                    }
                }
                if (!new_neighbor) {
                    if (neighbor->state != BGP_NEIGHBOR_DISCONNECTED && neighbor->state != BGP_NEIGHBOR_FAILED) {
                        close(neighbor->tcp_fd);
                        hashtable_remove_peer(i);
                    }
                } else {
                    if (neighbor->state != BGP_NEIGHBOR_DISCONNECTED && neighbor->state != BGP_NEIGHBOR_FAILED) {
                        if ((neighbor->state != BGP_NEIGHBOR_SENDING_KEEPALIVE && neighbor->state != BGP_NEIGHBOR_CONNECTED)|| neighbor->local_routes_sent != neighbor->local_routes_total
                            || new_neighbor->hold_time < neighbor->used_hold_time || neighbor->if_index != new_neighbor->if_index || memcmp(neighbor->local_ip, new_neighbor->local_ip, 16) || memcmp(neighbor->remote_ip, new_neighbor->remote_ip, 16) || neighbor->remote_asn_32bit != new_neighbor->remote_asn_32bit || neighbor->md5_password_length != new_neighbor->md5_password_length || (neighbor->md5_password_length && memcmp(neighbor->md5_password, new_neighbor->md5_password, neighbor->md5_password_length)) || neighbor->only_default_route != new_neighbor->only_default_route || neighbor->multihop != new_neighbor->multihop || (neighbor->multihop && memcmp(neighbor->gateway, new_neighbor->gateway, 16)) || neighbor->localpref != new_neighbor->localpref || neighbor->locally_withdrawn_routes_length
                        ) {
                            close(neighbor->tcp_fd);
                            hashtable_remove_peer(i);
                        } else {
                            new_neighbor->locally_withdrawn_routes_length = 0;
                            for (uint16 i = 0; i < bgp.route_count; ++i) {
                                if (bgp.announcing_groups[bgp.routes[i].bgp_announcing_group_id].announcement_specs[neighbor->id].announce) {
                                    struct bgp_route_s *route = &bgp.routes[i];
                                    bool still_there = false;
                                    for (uint16 y = 0; y < new_config.route_count; ++y) {
                                        if (new_config.routes[y].prefix_length == route->prefix_length && !memcmp(new_config.routes[y].prefix, route->prefix, (route->prefix_length + 7) / 8) &&
                                            new_config.announcing_groups[new_config.routes[y].bgp_announcing_group_id].announcement_specs[new_neighbor->id].announce) {
                                                still_there = true;
                                                break;
                                        }
                                    }
                                    if (!still_there) {
                                        new_neighbor->locally_withdrawn_routes_length += ((route->prefix_length + 7) / 8) + 1;
                                    }
                                }
                            }
                            if (new_neighbor->locally_withdrawn_routes_length > 4000) { // doesn't fit into one UPDATE message, easier to just reconnect
                                close(neighbor->tcp_fd);
                                hashtable_remove_peer(i);
                                continue;
                            } else if (new_neighbor->locally_withdrawn_routes_length > 0) {
                                new_neighbor->locally_withdrawn_routes_raw = alloc(new_neighbor->locally_withdrawn_routes_length);
                                for (uint16 i = 0, pos = 0; i < bgp.route_count; ++i) {
                                    if (bgp.announcing_groups[bgp.routes[i].bgp_announcing_group_id].announcement_specs[neighbor->id].announce) {
                                        struct bgp_route_s *route = &bgp.routes[i];
                                        bool still_there = false;
                                        for (uint16 y = 0; y < new_config.route_count; ++y) {
                                            if (new_config.routes[y].prefix_length == route->prefix_length && !memcmp(new_config.routes[y].prefix, route->prefix, (route->prefix_length + 7) / 8) &&
                                                new_config.announcing_groups[new_config.routes[y].bgp_announcing_group_id].announcement_specs[new_neighbor->id].announce) {
                                                    still_there = true;
                                                    break;
                                            }
                                        }
                                        if (!still_there) {
                                            uint8 *prefix_length = (uint8 *)new_neighbor->locally_withdrawn_routes_raw + pos;
                                            *prefix_length = route->prefix_length;
                                            memcpy((uint8 *)new_neighbor->locally_withdrawn_routes_raw + pos + 1, route->prefix, (route->prefix_length + 7) / 8);
                                            pos += ((route->prefix_length + 7) / 8) + 1;
                                        }
                                    }
                                }
                            }
                            new_neighbor->connected_at = neighbor->connected_at;
                            new_neighbor->tcp_fd = neighbor->tcp_fd;
                            new_neighbor->state = neighbor->state;
                            memcpy(new_neighbor->recv_buf, neighbor->recv_buf, neighbor->recv_bytes);
                            new_neighbor->recv_bytes = neighbor->recv_bytes;
                            new_neighbor->received_open = neighbor->received_open;
                            new_neighbor->routes_count = neighbor->routes_count;
                            new_neighbor->installed_routes_count = neighbor->installed_routes_count;
                            new_neighbor->last_keepalive_received = neighbor->last_keepalive_received;
                            new_neighbor->used_hold_time = neighbor->used_hold_time;
                            new_neighbor->supports_32bit = neighbor->supports_32bit;
                            new_neighbor->last_keepalive_sent = neighbor->last_keepalive_sent;
                            if (new_neighbor->id != neighbor->id) {
                                hashtable_update_peer_id(neighbor->id, new_neighbor->id);
                            }
                            if (neighbor->state == BGP_NEIGHBOR_SENDING_KEEPALIVE) {
                                memcpy(new_neighbor->send_buf, neighbor->send_buf, neighbor->total_bytes_to_send);
                                new_neighbor->sent_bytes = neighbor->sent_bytes;
                                new_neighbor->total_bytes_to_send = neighbor->total_bytes_to_send;
                                new_neighbor->time_started_sending = neighbor->time_started_sending;
                            } else if (new_neighbor->locally_withdrawn_routes_length > 0) {
                                construct_update_withdraw_message(new_neighbor);
                                new_neighbor->state = BGP_NEIGHBOR_SENDING_UPDATE;
                                new_neighbor->time_started_sending = now;
                            } else if (new_neighbor->local_routes_total > 0) {
                                construct_update_message(new_neighbor, &new_config);
                                new_neighbor->state = BGP_NEIGHBOR_SENDING_UPDATE;
                                new_neighbor->time_started_sending = now;
                            }
                        }
                    }
                }
            }
        }
    }
    free_settings(&bgp);
    memcpy(&bgp, &new_config, sizeof(struct bgp_main_s));
}

int main(int argc, char **argv) {
    signal(SIGUSR1, handle_sigusr1);
    signal(SIGHUP, handle_sighup);

    if (argc == 2 && strlen(argv[1]) == strlen("status") && !memcmp(argv[1], "status", sizeof("status"))) {
        pid_t pid = 0;
        parse_settings(&pid, &bgp);
        if (!pid || !bgp.status_port) {
            write(2, "Error: invalid config\n", strlen("Error: invalid config\n"));
            return 70;
        }
        int sock = socket(AF_INET6, SOCK_STREAM, 0);
        struct sockaddr_in6 addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(bgp.status_port);
        inet_pton(AF_INET6, "::1", &addr.sin6_addr);
        bind(sock, (struct sockaddr *)&addr, sizeof(addr));
        listen(sock, 1);
        kill(pid, SIGUSR1);
        int client = accept(sock, NULL, 0), tmp;
        char buf[4096];
        while ((tmp = read(client, buf, sizeof(buf))) > 0)
            write(1, buf, tmp);
        close(sock);
        return 0;
    } else if (argc == 2 && strlen(argv[1]) == strlen("reload") && !memcmp(argv[1], "reload", sizeof("reload"))) {
        pid_t pid = 0;
        parse_settings(&pid, &bgp);
        if (!pid) {
            write(2, "Error: invalid config\n", strlen("Error: invalid config\n"));
            return 70;
        }
        kill(pid, SIGHUP);
        return 0;
    } else if (argc != 1)
        return 80;
    
    parse_settings(NULL, &bgp);

    for (uint8 i = 0; i < bgp.neighbor_count; ++i) {
        struct bgp_neighbor_s *neighbor = &bgp.neighbors[i];
        if (!neighbor->only_default_route)
            bgp.has_non_default_route = true;
    }

    hashtable_init();

    bgp.netlink_fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    kernel_clear_table();

    log("MAIN", "Started", NULL, NULL);

    for (;;) {
        now = time(NULL);
        bool active = false;
        for (uint8 i = 0; i < bgp.neighbor_count; ++i) {
            handle_neighbor(i);
            if (bgp.neighbors[i].connected_at + 120 > now || bgp.neighbors[i].state <= 5)
                active = true;
        }
        if (send_status_flag) {
            send_status_flag = false;
            send_status();
        }
        if (reload_config_flag) {
            reload_config_flag = false;
            reload_config();
        }
        if (active)
            usleep(5000);
        else
            usleep(50000);
    }
    
    return 0;
}
