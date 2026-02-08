#include "bgp.h"

#define CONFIG_FILE "/etc/ltbgp/config"

void error(char *e) {
    write(2, "[CONFIG] ", strlen("[CONFIG] "));
    write(2, e, strlen(e));
    write(2, "\n", 1);
    exit(90);
}

char *strspace(char *str) {
    while (*str && !isspace(*str)) ++str;
    if (!*str) return NULL;
    return str;
}

#define SWITCH if (0) {}
#define CASE(str) else if (!memcmp(line_start, str, sizeof(str)))

void free_settings(struct bgp_main_s *bgp) {
    for (uint8 i = 0; i < bgp->neighbor_count; ++i) {
        if (bgp->neighbors[i].md5_password) free(bgp->neighbors[i].md5_password);
        free(bgp->neighbors[i].if_name);
        free(bgp->neighbors[i].name);
        if (bgp->neighbors[i].locally_withdrawn_routes_length > 0) free(bgp->neighbors[i].locally_withdrawn_routes_raw);
    }
    free(bgp->neighbors);
    for (uint16 i = 0; i < bgp->announcing_group_count; ++i) {
        for (uint8 y = 0; y < bgp->neighbor_count; ++y) {
            if (bgp->announcing_groups[i].announcement_specs[y].communities)
                free(bgp->announcing_groups[i].announcement_specs[y].communities);
            if (bgp->announcing_groups[i].announcement_specs[y].large_communities)
                free(bgp->announcing_groups[i].announcement_specs[y].large_communities);
        }
        free(bgp->announcing_groups[i].announcement_specs);
        free(bgp->announcing_groups[i].name);
    }
    free(bgp->announcing_groups);
    for (uint16 i = 0; i < bgp->routes_count; ++i)
        free(bgp->routes[i].prefix);
    free(bgp->routes);
}

void parse_settings(pid_t *read_pid, struct bgp_main_s *bgp) {
    memset(bgp, 0, sizeof(*bgp));

    int config_fd = open(CONFIG_FILE, O_RDONLY), tmp;
    if (config_fd == -1)
        error("Opening failed");

    uint32 length = lseek(config_fd, 0, SEEK_END), read_bytes = 0;
    lseek(config_fd, 0, SEEK_SET);

    char *config = alloc(length + 1), *line_start = config, *line_end;
    config[length] = '\0';
    
    while (read_bytes < length && (tmp = read(config_fd, config + read_bytes, length - read_bytes)) > 0)
        read_bytes += tmp;

    close(config_fd);
    
    if (read_bytes != length)
        error("Reading failed");
    
    char *config_second_pass = safe_strdup(config), *config_third_pass = safe_strdup(config), *config_fourth_pass = safe_strdup(config);

    // parse log, pid, table, id, asn, and count neighbors, groups and routes
    uint8 neighbor_count = 0;
    uint16 group_count = 1, route_count = 0;
    while ((line_start - config) < length && (line_end = strchr(line_start, '\n'))) {
        if (*line_start == '#' || line_start == line_end || *line_start == '.' || *line_start == '@') {
            line_start = line_end + 1;
            continue;
        }
        char *key_end = strspace(line_start);
        if (!key_end || key_end == line_end)
            error("Parsing error");
        char *value = key_end + 1;
        while (isspace(*value)) ++value;
        *key_end = '\0';
        *line_end = '\0';
        SWITCH
        CASE("log") {
            if (!read_pid) {
                bgp->log_fd = open(value, O_WRONLY | O_APPEND | O_CREAT);
                if (bgp->log_fd == -1)
                    error("Opening log file failed");
            }
        }
        CASE("pid") {
            if (!read_pid) {
                int pid_fd = open(value, O_WRONLY | O_CREAT | O_TRUNC);
                if (pid_fd == -1)
                    error("Opening pid file failed");
                pid_t pid = getpid();
                write(pid_fd, &pid, sizeof(pid));
                close(pid_fd);
            } else {
                int pid_fd = open(value, O_RDONLY);
                if (pid_fd == -1)
                    error("Opening pid file failed");
                pid_t pid;
                if (read(pid_fd, &pid, sizeof(pid)) != sizeof(pid))
                    error("Reading pid failed");
                close(pid_fd);
                *read_pid = pid;
            }
        }
        CASE("table") {
            bgp->routing_table_id = atoi(value);
            if (bgp->routing_table_id == 0)
                error("Routing table id may not be 0 (this can also be the result of an invalid number)");
        }
        CASE("id") {
            if (inet_pton(AF_INET, value, &bgp->identifier) != 1)
                error("Parsing 'id' failed");
        }
        CASE("asn") {
            long asn = atol(value);
            if (asn == 0 || asn == AS_TRANS)
                error("Invalid ASN");
            bgp->local_asn = asn > UINT16_MAX ? AS_TRANS : asn;
            bgp->local_asn_32bit = asn;
        }
        CASE("status_port") {
            int port = atoi(value);
            if (!port)
                error("Invalid port");
            bgp->status_port = port;
        }
        CASE("neighbor") {
            ++neighbor_count;
        }
        CASE("group") {
            ++group_count;
        }
        CASE("route") {
            ++route_count;
        }
        else {
            error("Unknown attribute");
        }
        line_start = line_end + 1;
    }
    if (!bgp->local_asn || !neighbor_count || !bgp->routing_table_id)
        error("Missing parameter(s)");
    bgp->neighbor_count = neighbor_count;
    bgp->neighbors = alloc(sizeof(struct bgp_neighbor_s) * neighbor_count);
    memset(bgp->neighbors, 0, sizeof(struct bgp_neighbor_s) * neighbor_count);
    struct bgp_neighbor_s *current_neighbor = &bgp->neighbors[0];
    uint8 neighbor_id = 0;
    bool is_parsing_neighbor = false;
    line_start = config_second_pass;
    // parse neighbors
    while ((line_start - config_second_pass) < length && (line_end = strchr(line_start, '\n'))) {
        if (*line_start == '#' || line_start == line_end || *line_start == '@') {
            line_start = line_end + 1;
            continue;
        }
        char *key_end = strspace(line_start);
        if (!key_end || key_end == line_end)
            error("Parsing error");
        char *value = key_end + 1;
        while (isspace(*value)) ++value;
        *key_end = '\0';
        *line_end = '\0';
        if (*line_start == '.') {
            if (!is_parsing_neighbor)
                error("Unexpected dot");
            ++line_start;
            SWITCH
            CASE("hold_time") {
                current_neighbor->hold_time = atoi(value);
                if (current_neighbor->hold_time <= 2)
                    error("Invalid hold time (> 2)");
            }
            CASE("routelimit") {
                current_neighbor->routelimit = atoll(value);
                if (!current_neighbor->routelimit)
                    error("Invalid routelimit (>= 1)");
            }
            CASE("multihop") {
                current_neighbor->multihop = atoi(value);
                if (!current_neighbor->multihop)
                    error("Invalid multihop (>= 1)");
            }
            CASE("localpref") {
                current_neighbor->localpref = atoi(value);
                if (!current_neighbor->localpref)
                    error("Invalid localpref (>= 1)");
            }
            CASE("interface") {
                current_neighbor->if_name = safe_strdup(value);
                current_neighbor->if_index = if_nametoindex(value);
                if (!current_neighbor->if_index)
                    error("Invalid interface");
            }
            CASE("local_ip") {
                if (inet_pton(AF_INET6, value, current_neighbor->local_ip) != 1)
                    error("Invalid local_ip");
            }
            CASE("gateway") {
                if (inet_pton(AF_INET6, value, current_neighbor->gateway) != 1)
                    error("Invalid gateway");
            }
            CASE("remote_ip") {
                if (inet_pton(AF_INET6, value, current_neighbor->remote_ip) != 1)
                    error("Invalid remote_ip");
            }
            CASE("remote_asn") {
                long asn = atol(value);
                if (asn == 0 || asn == AS_TRANS)
                    error("Invalid ASN");
                current_neighbor->remote_asn = asn > UINT16_MAX ? AS_TRANS : asn;
                current_neighbor->remote_asn_32bit = asn;
            }
            CASE("only_default_route") {
                current_neighbor->only_default_route = strlen(value) == 4 && !memcmp(value, "true", 5);
            }
            CASE("md5_password_file") {
                int md5_password_fd = open(value, O_RDONLY), tmp;
                if (md5_password_fd == -1)
                    error("Opening md5_password_file failed");
                uint16 length = lseek(md5_password_fd, 0, SEEK_END), read_bytes = 0;
                lseek(md5_password_fd, 0, SEEK_SET);
                char *md5_password = alloc(length);
                while (read_bytes < length && (tmp = read(md5_password_fd, md5_password + read_bytes, length - read_bytes)) > 0)
                    read_bytes += tmp;
                close(md5_password_fd);
                if (read_bytes != length)
                    error("Reading md5_password_file failed");
                current_neighbor->md5_password = (uint8 *)md5_password;
                current_neighbor->md5_password_length = length;
            }
            else {
                error("Unknown attribute");
            }
            line_start = line_end + 1;
            continue;
        }
        SWITCH
        CASE("neighbor") {
            if (is_parsing_neighbor) {
                ++neighbor_id;
                current_neighbor = &bgp->neighbors[neighbor_id];
            }
            memset(current_neighbor->send_buf, 0xFF, 16);
            current_neighbor->state = BGP_NEIGHBOR_DISCONNECTED;
            is_parsing_neighbor = true;
            current_neighbor->name = safe_strdup(value);
            current_neighbor->id = neighbor_id;
        }
        line_start = line_end + 1;
    }
    bgp->announcing_group_count = group_count;
    bgp->announcing_groups = alloc(sizeof(struct bgp_announcing_group_s) * group_count);
    memset(bgp->announcing_groups, 0, sizeof(struct bgp_announcing_group_s) * group_count);
    for (uint16 i = 0; i < group_count; ++i) {
        bgp->announcing_groups[i].announcement_specs = alloc(sizeof(struct bgp_announcement_specs_s) * neighbor_count);
        memset(bgp->announcing_groups[i].announcement_specs, 0, sizeof(struct bgp_announcement_specs_s) * neighbor_count);
    }
    bgp->announcing_groups[0].name = safe_strdup("default");
    for (uint8 i = 0; i < neighbor_count; ++i)
        bgp->announcing_groups[0].announcement_specs[i].announce = true;
    line_start = config_third_pass;
    struct bgp_announcing_group_s *current_group = &bgp->announcing_groups[1];
    uint8 group_id = 1;
    bool is_parsing_group = false;
    // parse groups
    while ((line_start - config_third_pass) < length && (line_end = strchr(line_start, '\n'))) {
        if (*line_start == '#' || line_start == line_end || *line_start == '.') {
            line_start = line_end + 1;
            continue;
        }
        char *key_end = strspace(line_start);
        char *value;
        if (!key_end) {
            key_end = line_end;
            value = NULL;
        } else {
            *key_end = '\0';
            value = key_end + 1;
            while (isspace(*value)) ++value;
        }
        *line_end = '\0';
        if (*line_start == '@') {
            ++line_start;
            uint8 neighbor_name_length = strlen(line_start);
            for (uint8 i = 0; i < neighbor_count; ++i) {
                if (strlen(bgp->neighbors[i].name) == neighbor_name_length && !memcmp(bgp->neighbors[i].name, line_start, neighbor_name_length)) {
                    struct bgp_announcement_specs_s *specs = &current_group->announcement_specs[i];
                    specs->announce = true;
                    if (!value)
                        break;
                    char *endptr;
                    long prepends = strtol(value, &endptr, 10);
                    if (endptr == value)
                        break;
                    specs->prepend_n_times = prepends;
                    uint8 community_count = 0, large_community_count = 0;
                    value = endptr;
                    char *value_start = value;
                    for (;;) {
                        while (*value && isspace(*value)) ++value;
                        if (!*value)
                            break;
                        /*long part1 = */strtol(value, &endptr, 10);
                        if (endptr == value || *endptr != ':')
                            error("Error parsing group");
                        value = endptr + 1;
                        /*long part2 = */strtol(value, &endptr, 10);
                        if (endptr == value)
                            error("Error parsing group");
                        if (*endptr)
                            value = endptr + 1;
                        if (*endptr == ':') {
                            /*long part3 = */strtol(value, &endptr, 10);
                            if (endptr == value || (*endptr && !isspace(*endptr)))
                                error("Error parsing group");
                            value = endptr + 1;
                            ++large_community_count;
                            if (!*endptr)
                                break;
                        } else {
                            ++community_count;
                            if (!*endptr)
                                break;
                        }
                    }
                    specs->communities_count = community_count;
                    specs->large_communities_count = large_community_count;
                    if (specs->communities_count)
                        specs->communities = alloc(4 * community_count);
                    if (specs->large_communities_count)
                        specs->large_communities = alloc(12 * large_community_count);
                    value = value_start;
                    community_count = 0, large_community_count = 0;
                    for (;;) {
                        while (*value && isspace(*value)) ++value;
                        if (!*value)
                            break;
                        long part1 = strtol(value, &endptr, 10);
                        if (endptr == value || *endptr != ':')
                            error("Error parsing group");
                        value = endptr + 1;
                        long part2 = strtol(value, &endptr, 10);
                        if (endptr == value)
                            error("Error parsing group");
                        if (*endptr)
                            value = endptr + 1;
                        if (*endptr == ':') {
                            long part3 = strtol(value, &endptr, 10);
                            if (endptr == value || (*endptr && !isspace(*endptr)))
                                error("Error parsing group");
                            value = endptr + 1;
                            uint32 *parts = (uint32 *)((void *)specs->large_communities + 12 * large_community_count);
                            *parts = part1;
                            ++parts;
                            *parts = part2;
                            ++parts;
                            *parts = part3;
                            ++large_community_count;
                            if (!*endptr)
                                break;
                        } else {
                            uint16 *parts = (uint16 *)((void *)specs->communities + 4 * community_count);
                            *parts = part1;
                            ++parts;
                            *parts = part2;
                            ++community_count;
                            if (!*endptr)
                                break;
                        }
                    }
                    break;
                }
            }
        }
        SWITCH
        CASE("group") {
            if (is_parsing_group) {
                ++group_id;
                current_group = &bgp->announcing_groups[group_id];
            }
            is_parsing_group = true;
            current_group->name = safe_strdup(value);
        }
        line_start = line_end + 1;
    }

    bgp->route_count = route_count;
    bgp->routes = alloc(sizeof(struct bgp_route_s) * route_count);
    memset(bgp->routes, 0, sizeof(struct bgp_route_s) * route_count);
    uint16 route_id = 0;
    line_start = config_fourth_pass;
    while ((line_start - config_fourth_pass) < length && (line_end = strchr(line_start, '\n'))) {
        if (*line_start == '#' || line_start == line_end || *line_start == '.' || *line_start == '@') {
            line_start = line_end + 1;
            continue;
        }
        char *key_end = strspace(line_start);
        if (!key_end || key_end == line_end)
            error("Parsing error");
        char *value = key_end + 1;
        while (isspace(*value)) ++value;
        *key_end = '\0';
        *line_end = '\0';
        SWITCH
        CASE("route") {
            struct bgp_route_s *route = &bgp->routes[route_id];
            uint8 prefix[16];
            char *pos = strchr(value, '/');
            if (!pos)
                error("Error parsing route");
            char *endptr;
            *pos = '\0';
            long prefix_length = strtol(pos + 1, &endptr, 10);
            if (pos + 1 == endptr || prefix_length > 128 || prefix_length < 0)
                error("Error parsing route");
            route->prefix_length = prefix_length;
            if (inet_pton(AF_INET6, value, prefix) != 1)
                error("Error parsing route");
            route->prefix = alloc((prefix_length + 7) / 8);
            memcpy(route->prefix, prefix, (prefix_length + 7) / 8);
            if (prefix_length % 8 != 0)
                route->prefix[((prefix_length + 7) / 8) - 1] &= (0xFF << (8 - (prefix_length % 8)));
            while (*endptr && isspace(*endptr)) ++endptr;
            if (!endptr)
                error("Error parsing route");
            uint8 group_name_length = strlen(endptr);
            for (uint16 i = 0; i < group_count; ++i) {
                if (strlen(bgp->announcing_groups[i].name) == group_name_length && !memcmp(bgp->announcing_groups[i].name, endptr, group_name_length)) {
                    route->bgp_announcing_group_id = i;
                    break;
                }
            }
            ++route_id;
        }
        line_start = line_end + 1;
    }
    for (uint8 i = 0; i < neighbor_count; ++i) {
        uint16 routes_count = 0;
        for (uint8 y = 0; y < route_count; ++y) {
            if (bgp->announcing_groups[bgp->routes[y].bgp_announcing_group_id].announcement_specs[i].announce)
                ++routes_count;
        }
        bgp->neighbors[i].local_routes_total = routes_count;
    }
    free(config);
    free(config_second_pass);
    free(config_third_pass);
    free(config_fourth_pass);
}
