#ifndef PACKET_HPP_
#define PACKET_HPP_

struct ip_prefix {
    uint8_t len;
    std::vector<uint8_t> address;

    ip_prefix( uint8_t *data, uint8_t l ):
        len( l )
    {
        auto bytes = l / 8;
        if( l % 8 != 0 ) {
            bytes++;
        }
        address = std::vector<uint8_t>{ data, data + bytes };
    }
};

enum class path_attribute : uint8_t {
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

struct path_attr {

}__attribute__((__packed__));

using nlri = ip_prefix;
using withdrawn_routes = ip_prefix;

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

    std::tuple<std::vector<nlri>,std::vector<nlri>> process_update() {
        std::vector<nlri> withdrawn_routes;
        auto header = get_header();
        auto update_data = data + sizeof( bgp_header );
        auto update_len = bswap16( header->length ) - sizeof( bgp_header );
        log( "Size of UPDATE payload: "s + std::to_string( update_len ) );

        // parsing withdrawn routes
        auto len = bswap16( *reinterpret_cast<uint16_t*>( update_data ) );
        log( "Length of withdrawn routes: "s + std::to_string( len ) );
        uint16_t offset = sizeof( len );
        while( len > 0 ) {
            if( offset >= update_len ) {
                log( "Error on parsing message" );
                return { {}, {} };
            }
            uint8_t nlri_len = *reinterpret_cast<uint8_t*>( update_data + offset );
            withdrawn_routes.emplace_back( update_data + offset + 1, nlri_len );
        }
        len = bswap16( *reinterpret_cast<uint16_t*>( update_data + offset ) );
        log( "Length of path attributes: "s + std::to_string( len ) );

        // todo path attrs
        offset += sizeof( len ) + len;

        // parsing NLRI
        len = update_len - offset;
        log( "Length of NLRI: "s + std::to_string( len ) );
        std::vector<nlri> routes;
        while( len > 0 ) {
            if( offset >= update_len ) {
                log( "Error on parsing message" );
                return { {}, {} };
            }
            uint8_t nlri_len = *reinterpret_cast<uint8_t*>( update_data + offset );
            routes.emplace_back( update_data + offset + 1, nlri_len );
            auto bytes = nlri_len / 8;
            if( nlri_len % 8 != 0 ) {
                bytes++;
            }
            len -= sizeof( nlri_len ) + bytes;
        }

        return { withdrawn_routes, routes };
    }
};

#endif