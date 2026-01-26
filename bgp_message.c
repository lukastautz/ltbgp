#include "bgp_message.h"

static const uint8 expected_marker[16] = {
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
};

void validate_bgp_message(void *bgp_message, uint16 max_length, struct bgp_message_validator_s *result) {
    if (max_length < sizeof(struct bgp_message_header_s)) {
        result->state = BGP_MESSAGE_INCOMPLETE;
        return;
    }
    struct bgp_message_header_s *header = (struct bgp_message_header_s *)bgp_message;
    uint16 header_length = __bswap_16(header->length);
    if (header->type == BGP_TYPE_NOTIFICATION) {
        result->state = BGP_MESSAGE_CONNECTION_CLOSED;
        result->suberror_str = "Unspecific";
        if (header_length < sizeof(struct bgp_message_header_s) + 2) {
            result->error_str = "Received invalid NOTIFICATION message";
        } else {
            struct bgp_notification_header_s *notification = (struct bgp_notification_header_s *)(bgp_message + sizeof(struct bgp_message_header_s));
            switch (notification->error) {
                case 1:
                    result->error_str = "Message Header Error";
                    switch (notification->suberror) {
                        case 1: result->suberror_str = "Connection Not Synchronized"; break;
                        case 2: result->suberror_str = "Bad Message Length"; break;
                        case 3: result->suberror_str = "Bad Message Type"; break;
                    }
                    break;
                case 2:
                    result->error_str = "OPEN Header Error";
                    switch (notification->suberror) {
                        case 1: result->suberror_str = "Unsupported Version Number"; break;
                        case 2: result->suberror_str = "Bad Peer AS"; break;
                        case 3: result->suberror_str = "Bad BGP Identifier"; break;
                        case 4: result->suberror_str = "Unsupported Optional Parameter"; break;
                        case 5: result->suberror_str = "[Deprecated error]"; break;
                        case 6: result->suberror_str = "Unacceptable Hold Time"; break;
                    }
                    break;
                case 3:
                    result->error_str = "UPDATE Message Error";
                    switch (notification->suberror) {
                        case 1: result->suberror_str = "Malformed Attribute List"; break;
                        case 2: result->suberror_str = "Unrecognized Well-known Attribute"; break;
                        case 3: result->suberror_str = "Missing Well-known Attribute"; break;
                        case 4: result->suberror_str = "Attribute Flags Error"; break;
                        case 5: result->suberror_str = "Attribute Length Error"; break;
                        case 6: result->suberror_str = "Invalid ORIGIN Attribute"; break;
                        case 7: result->suberror_str = "[Deprecated error]"; break;
                        case 8: result->suberror_str = "Invalid NEXT_HOP Attribute"; break;
                        case 9: result->suberror_str = "Optional Attribute Error"; break;
                        case 10: result->suberror_str = "Invalid Network Field"; break;
                        case 11: result->suberror_str = "Malformed AS_PATH"; break;
                    }
                    break;
                case 4:
                    result->error_str = "Hold Timer Expired";
                    break;
                case 5:
                    result->error_str = "Finite State Machine Error";
                    break;
                case 6:
                    result->error_str = "Cease";
                    break;
                default:
                    result->error_str = "Unknown error";
            }
        }
        return;
    }
    if (memcmp(header->marker, expected_marker, 16)) {
        result->state = BGP_MESSAGE_INVALID;
        result->error = 1, result->error_str = "Message Header Error";
        result->suberror = 1, result->suberror_str = "Connection Not Synchronized";
        return;
    }
    if (header->type == 0 || header->type > 4) {
        result->state = BGP_MESSAGE_INVALID;
        result->error = 1, result->error_str = "Message Header Error";
        result->suberror = 3, result->suberror_str = "Bad Message Type";
        return;
    }
    if (header_length < 19 || header_length > 4096 ||
        (header->type == BGP_TYPE_OPEN && header_length < 29) ||
        (header->type == BGP_TYPE_UPDATE && header_length < 23) ||
        (header->type == BGP_TYPE_KEEPALIVE && header_length != 19)) {
        result->state = BGP_MESSAGE_INVALID;
        result->error = 1, result->error_str = "Message Header Error";
        result->suberror = 2, result->suberror_str = "Bad Message Length";
        return;
    }
    if (max_length < header_length) {
        result->state = BGP_MESSAGE_INCOMPLETE;
        return;
    }
    switch (header->type) {
        case BGP_TYPE_KEEPALIVE:
            result->state = BGP_MESSAGE_VALID;
            return;
        case BGP_TYPE_OPEN: {
            struct bgp_open_header_s *open_header = (struct bgp_open_header_s *)(bgp_message + sizeof(struct bgp_message_header_s));
            if (open_header->version != 4) {
                // RFC incompliant, data is not set to supported version
                result->state = BGP_MESSAGE_INVALID;
                result->error = 2, result->error_str = "OPEN Message Error";
                result->suberror = 1, result->suberror_str = "Unsupported Version Number";
                return;
            }
            if (__bswap_16(open_header->hold_time) <= 2) {
                result->state = BGP_MESSAGE_INVALID;
                result->error = 2, result->error_str = "OPEN Message Error";
                result->suberror = 6, result->suberror_str = "Unacceptable Hold Time";
                return;
            }
            if ((open_header->optional_parameter_length + sizeof(struct bgp_open_header_s) + sizeof(struct bgp_message_header_s)) != header_length) {
                result->state = BGP_MESSAGE_INVALID;
                result->error = 2, result->error_str = "OPEN Message Error";
                result->suberror = 0, result->suberror_str = "Invalid optional parameter length";
                return;
            }
            uint16 parsed_length = 0;
            while ((parsed_length + 2) <= open_header->optional_parameter_length) {
                struct bgp_open_optional_parameter_header_s *parameter_header = (struct bgp_open_optional_parameter_header_s *)(bgp_message + sizeof(struct bgp_message_header_s) + sizeof(struct bgp_open_header_s) + parsed_length);
                parsed_length += 2 + parameter_header->data_length;                
            }
            if (parsed_length != open_header->optional_parameter_length) {
                result->state = BGP_MESSAGE_INVALID;
                result->error = 2, result->error_str = "OPEN Message Error";
                result->suberror = 0, result->suberror_str = "Invalid optional parameter length";
                return;
            }
            bool supports_ipv6 = false, supports_32bit = false;
            parsed_length = 0;
            while ((parsed_length + 2) <= open_header->optional_parameter_length) {
                struct bgp_open_optional_parameter_header_s *parameter_header = (struct bgp_open_optional_parameter_header_s *)(bgp_message + sizeof(struct bgp_message_header_s) + sizeof(struct bgp_open_header_s) + parsed_length);
                if (parameter_header->type != BGP_OPEN_OPTIONAL_PARAMETER_CAPABILITIES) {
                    result->state = BGP_MESSAGE_INVALID;
                    result->error = 2, result->error_str = "OPEN Message Error";
                    result->suberror = 4, result->suberror_str = "Unsupported Optional Parameter";
                    return;
                }
                uint16 capability_parsed_length = 0;
                while ((capability_parsed_length + 2) <= parameter_header->data_length) {
                    struct bgp_capability_header_s *capability_header = (struct bgp_capability_header_s *)((void *)parameter_header + sizeof(struct bgp_open_optional_parameter_header_s) + capability_parsed_length);
                    capability_parsed_length += 2 + capability_header->data_length;
                }
                if (capability_parsed_length != parameter_header->data_length) {
                    result->state = BGP_MESSAGE_INVALID;
                    result->error = 2, result->error_str = "OPEN Message Error";
                    result->suberror = 0, result->suberror_str = "Invalid capability optional parameter";
                    return;
                }
                capability_parsed_length = 0;
                while ((capability_parsed_length + 2) <= parameter_header->data_length) {
                    struct bgp_capability_header_s *capability_header = (struct bgp_capability_header_s *)((void *)parameter_header + sizeof(struct bgp_open_optional_parameter_header_s) + capability_parsed_length);
                    if (capability_header->code == BGP_CAPABILITY_CODE_4_OCTET_ASNS || capability_header->code == BGP_CAPABILITY_CODE_MULTIPROTOCOL_EXTENSIONS) {
                        if (capability_header->data_length != 4) {
                            result->state = BGP_MESSAGE_INVALID;
                            result->error = 2, result->error_str = "OPEN Message Error";
                            result->suberror = 0, result->suberror_str = "Invalid capability";
                            return;
                        }
                        if (capability_header->code == BGP_CAPABILITY_CODE_MULTIPROTOCOL_EXTENSIONS) {
                            struct bgp_capability_multiprotocol_s *capability_multiprotocol = (struct bgp_capability_multiprotocol_s *)((void *)capability_header + sizeof(struct bgp_capability_header_s));
                            if (__bswap_16(capability_multiprotocol->AFI) == AFI_IPV6 && capability_multiprotocol->SAFI == SAFI_UNICAST)
                                supports_ipv6 = true;
                        } else
                            supports_32bit = true;
                    }
                    capability_parsed_length += 2 + capability_header->data_length;
                }
                parsed_length += 2 + parameter_header->data_length;                
            }
            if (!supports_ipv6) {
                result->state = BGP_MESSAGE_INVALID;
                result->error = 2, result->error_str = "OPEN Message Error";
                result->suberror = 0, result->suberror_str = "Missing IPv6 capability";
                return;
            }
            result->state = supports_32bit ? BGP_MESSAGE_VALID_SUPPORTS_32BIT_ASNS : BGP_MESSAGE_VALID;
            return;
        }
        case BGP_TYPE_UPDATE: {
            uint16 withdrawn_routes_length = *(uint16 *)(bgp_message + sizeof(struct bgp_message_header_s));
            withdrawn_routes_length = __bswap_16(withdrawn_routes_length);
            if ((sizeof(struct bgp_message_header_s) + withdrawn_routes_length + 4) > header_length) {
                result->state = BGP_MESSAGE_INVALID;
                result->error = 3, result->error_str = "UPDATE Message Error";
                result->suberror = 0, result->suberror_str = "Invalid length field";
                return;
            }
            uint16 path_attributes_length = *(uint16 *)(bgp_message + sizeof(struct bgp_message_header_s) + 2 + withdrawn_routes_length);
            path_attributes_length = __bswap_16(path_attributes_length);
            if ((sizeof(struct bgp_message_header_s) + withdrawn_routes_length + 4 + path_attributes_length) > header_length) {
                result->state = BGP_MESSAGE_INVALID;
                result->error = 3, result->error_str = "UPDATE Message Error";
                result->suberror = 0, result->suberror_str = "Invalid length field";
                return;
            }
            // withdrawn routes and NLRI are ignored as they can only contain IPv4 routes
            uint16 parsed_length = 0;
            while ((parsed_length + 3) <= path_attributes_length) {
                void *pos = bgp_message + sizeof(struct bgp_message_header_s) + withdrawn_routes_length + 4 + parsed_length;
                uint8 attribute_flags = *(uint8 *)pos;
                //uint8 attribute_type_code = *(uint8 *)(pos + 1);
                uint16 length = *(uint8 *)(pos + 2);
                if ((attribute_flags >> 4) & 1) { // extended length
                    length = *(uint16 *)(pos + 2);
                    length = __bswap_16(length);
                    ++parsed_length;
                }
                parsed_length += 3 + length;
            }
            if (parsed_length != path_attributes_length) {
                result->state = BGP_MESSAGE_INVALID;
                result->error = 3, result->error_str = "UPDATE Message Error";
                result->suberror = 1, result->suberror_str = "Malformed Attribute List";
                return;
            }
            parsed_length = 0;
            while ((parsed_length + 3) <= path_attributes_length) {
                void *pos = bgp_message + sizeof(struct bgp_message_header_s) + withdrawn_routes_length + 4 + parsed_length;
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
                // RFC incompliant, only AS_PATH, MP_REACH_NLRI and MP_UNREACH_NLRI as checked for correctness
                switch (attribute_type_code) {
                    case BGP_UPDATE_TYPECODE_AS_PATH:
                        // RFC incompliant as only the path length is needed
                        if (length < 2) {
                            result->state = BGP_MESSAGE_INVALID;
                            result->error = 3, result->error_str = "UPDATE Message Error";
                            result->suberror = 11, result->suberror_str = "Malformed AS_PATH";
                            return;
                        }
                        break;
                    case BGP_UPDATE_TYPECODE_MP_REACH_NLRI:
                    case BGP_UPDATE_TYPECODE_MP_UNREACH_NLRI: {
                        struct bgp_update_mp_header_s *mp_header = (struct bgp_update_mp_header_s *)pos;
                        if (__bswap_16(mp_header->AFI) == AFI_IPV6 && mp_header->SAFI == SAFI_UNICAST) {
                            if (attribute_type_code == BGP_UPDATE_TYPECODE_MP_REACH_NLRI) {
                                uint8 next_hop_length = *(uint8 *)(pos + sizeof(struct bgp_update_mp_header_s));
                                if (next_hop_length != 16 && next_hop_length != 32) {
                                    result->state = BGP_MESSAGE_INVALID;
                                    result->error = 3, result->error_str = "UPDATE Message Error";
                                    result->suberror = 0, result->suberror_str = "Incorrect next hop length";
                                    return;
                                }
                                length -= 2 + next_hop_length, pos += 2 + next_hop_length; // next hop length (1 octet) + next hop + reserved (1 octet)
                            }
                            // check NLRI
                            length -= sizeof(struct bgp_update_mp_header_s), pos += sizeof(struct bgp_update_mp_header_s);
                            uint16 parsed_nlri_length = 0;
                            while ((parsed_nlri_length + 1) <= length) {
                                uint8 prefix_length = *(uint8 *)pos;
                                prefix_length += 7;
                                prefix_length /= 8;
                                parsed_nlri_length += prefix_length + 1;
                                pos += prefix_length + 1;
                            }
                            if (parsed_nlri_length != length) {
                                result->state = BGP_MESSAGE_INVALID;
                                result->error = 3, result->error_str = "UPDATE Message Error";
                                result->suberror = 0, result->suberror_str = "Malformed MP_NLRI";
                                return;
                            }
                        }
                        break;
                    }
                }
            }
            result->state = BGP_MESSAGE_VALID;
            return;
        }
    }
}

