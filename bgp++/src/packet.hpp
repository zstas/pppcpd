#ifndef PACKET_HPP_
#define PACKET_HPP_

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

    bgp_packet( uint8_t *begin, std::size_t l ):
        data( begin ),
        length( l )
    {}

    bgp_header* get_header() {
        return reinterpret_cast<bgp_header*>( data );
    }

    bgp_open* get_open() {
        return reinterpret_cast<bgp_open*>( data + sizeof( bgp_header ) );
    }

};

#endif