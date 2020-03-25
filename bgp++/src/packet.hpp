#ifndef PACKET_HPP_
#define PACKET_HPP_

enum class PATH_ATTRIBUTE : uint8_t {
    ORIGIN = 1,
    AS_PATH = 2,
    NEXT_HOP = 3,
    MULTI_EXIT_DISC = 4,
    LOCAL_PREF = 5,
    ATOMIC_AGGREGATE = 6,
    AGGREGATOR = 7,
};

enum class ORIGIN : uint8_t {
    IGP = 0,
    EGP = 1,
    INCOMPLETE = 2,
};

namespace std {
    std::string to_string( PATH_ATTRIBUTE attr );
    std::string to_string( ORIGIN origin );
}

struct path_attr_header {
    uint8_t unused:4;
    uint8_t extended_length:1;
    uint8_t partial:1;
    uint8_t transitive:1;
    uint8_t optional:1;
    PATH_ATTRIBUTE type;
    union {
        uint16_t ext_len;
        uint8_t len;
    };
}__attribute__((__packed__));

struct path_attr_t {
    uint8_t optional:1;
    uint8_t transitive:1;
    uint8_t partial:1;
    uint8_t extended_length:1;
    uint8_t unused:4;
    PATH_ATTRIBUTE type;
    std::vector<uint8_t> bytes;

    path_attr_t( path_attr_header *header );

    std::string to_string();
    uint32_t get_u32();
};

using nlri = prefix_v4;
using withdrawn_routes = prefix_v4;

enum class bgp_type : uint8_t {
    OPEN = 1,
    UPDATE = 2,
    NOTIFICATION = 3,
    KEEPALIVE = 4,
    ROUTE_REFRESH = 5,
};

struct bgp_header {
    std::array<uint8_t,16> marker;
    uint16_t length;
    bgp_type type;
}__attribute__((__packed__));

struct bgp_open {
    uint8_t version;
    uint16_t my_as;
    uint16_t hold_time;
    uint32_t bgp_id;
    uint8_t len;
}__attribute__((__packed__));

struct bgp_packet {
    bgp_header *header = nullptr;

    uint8_t *data;
    std::size_t length;

    bgp_packet( uint8_t *begin, std::size_t l );
    bgp_header* get_header();
    bgp_open* get_open();
    std::tuple<std::vector<nlri>,std::vector<path_attr_t>,std::vector<nlri>> process_update();
};

#endif