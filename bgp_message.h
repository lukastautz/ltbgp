#ifndef INCLUDE_BGP_MESSAGE
#define INCLUDE_BGP_MESSAGE

#include "include.h"

struct PACKED bgp_message_header_s {
    uint8 marker[16]; // set to all ones
    uint16 NEEDS_CONVERT length;
    uint8 type;
};

enum bgp_message_validator_state_e {
    BGP_MESSAGE_VALID,
    BGP_MESSAGE_VALID_SUPPORTS_32BIT_ASNS,
    BGP_MESSAGE_INCOMPLETE,
    BGP_MESSAGE_INVALID,
    BGP_MESSAGE_CONNECTION_CLOSED
};

struct bgp_message_validator_s {
    enum bgp_message_validator_state_e state;
    uint8 error;
    uint8 suberror;
    char *error_str;
    char *suberror_str;
};

#define BGP_TYPE_OPEN 1
#define BGP_TYPE_UPDATE 2
#define BGP_TYPE_NOTIFICATION 3
#define BGP_TYPE_KEEPALIVE 4

struct PACKED bgp_open_header_s {
    uint8 version; // =4
    uint16 NEEDS_CONVERT asn; // AS_TRANS if LOCAL_ASN > UINT16_MAX
    uint16 NEEDS_CONVERT hold_time;
    uint32 identifier;
    uint8 optional_parameter_length;
};

struct PACKED bgp_open_optional_parameter_header_s {
    uint8 type;
#define BGP_OPEN_OPTIONAL_PARAMETER_CAPABILITIES 2
    uint8 data_length;
};

struct PACKED bgp_capability_header_s {
    uint8 code;
#define BGP_CAPABILITY_CODE_MULTIPROTOCOL_EXTENSIONS 1
#define BGP_CAPABILITY_CODE_4_OCTET_ASNS 65
    uint8 data_length;
};

struct PACKED bgp_capability_multiprotocol_s {
#define AFI_IPV6 2
    uint16 NEEDS_CONVERT AFI;
    uint8 res;
#define SAFI_UNICAST 1
    uint8 SAFI;
};

struct PACKED bgp_notification_header_s {
    uint8 error;
    uint8 suberror;
};

struct PACKED bgp_update_mp_header_s {
    uint16 NEEDS_CONVERT AFI;
    uint8 SAFI;
};

struct PACKED bgp_update_path_attribute_s { // ONLY for sending as length is here only one byte (extended length = 0)
    uint8 flags;
    uint8 typecode;
    uint8 length;
};

struct PACKED bgp_update_mp_reach_nrli_ipv6_s {
    uint16 NEEDS_CONVERT AFI;
    uint8 SAFI;
    uint8 next_hop_length; //=16
    uint8 next_hop[16];
    uint8 res;
};

#define BGP_UPDATE_TYPECODE_ORIGIN 1
#define BGP_UPDATE_TYPECODE_AS4_PATH 17
#define BGP_UPDATE_TYPECODE_AS_PATH 2
#define BGP_UPDATE_TYPECODE_COMMUNITIES 8
#define BGP_UPDATE_TYPECODE_LARGE_COMMUNITIES 32
#define BGP_UPDATE_TYPECODE_MP_REACH_NLRI 14
#define BGP_UPDATE_TYPECODE_MP_UNREACH_NLRI 15

void validate_bgp_message(void *bgp_message, uint16 max_length, struct bgp_message_validator_s *result);

#endif
