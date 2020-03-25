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

namespace std {
    std::string to_string( PATH_ATTRIBUTE attr );
}

enum class ORIGIN : uint8_t {
    IGP = 0,
    EGP = 1,
    INCOMPLETE = 2,
};

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

    // path_attr_t() = default;
    path_attr_t( path_attr_header *header ):
        optional( header->optional ),
        transitive( header->transitive ),
        partial( header->partial ),
        extended_length( header->extended_length ),
        type( header->type )
    {
        auto len = ( header->extended_length == 1 ? bswap16( header->ext_len ) : header->len );
        auto body = reinterpret_cast<uint8_t*>( header ) + 2 + ( header->extended_length ? 2 : 1 );
        bytes = std::vector<uint8_t>( body, body + len );
    }

    std::string to_string() {
        std::string out;

        out += "Type: "s + std::to_string( type ) + " ";
        out += "Length: "s + std::to_string( bytes.size() ) + " ";
        out += "Value: ";
        switch( type ) {
        case PATH_ATTRIBUTE::ORIGIN:
            out += origin_dump();
            break;
        case PATH_ATTRIBUTE::NEXT_HOP: 
            out += address_v4( get_u32() ).to_string();
            break;
        case PATH_ATTRIBUTE::LOCAL_PREF:
            out += std::to_string( get_u32() );
            break;
        case PATH_ATTRIBUTE::MULTI_EXIT_DISC:
            out += std::to_string( get_u32() );
            break;
        default:
            out += "NA";
        }

        return out;
    }

    uint32_t get_u32() {
        return bswap32( *reinterpret_cast<uint32_t*>( bytes.data() ) );
    }

    std::string origin_dump() const {
        auto origin = static_cast<ORIGIN>( bytes[0] );
        switch( origin ) {
        case ORIGIN::EGP:
            return "EGP";
        case ORIGIN::IGP:
            return "IGP";
        case ORIGIN::INCOMPLETE:
            return "INCOMPLETE";
        }
        return "ERROR";
    }
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

    std::tuple<std::vector<nlri>,std::vector<path_attr_t>,std::vector<nlri>> process_update() {
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
                return { {}, {}, {} };
            }
            uint8_t nlri_len = *reinterpret_cast<uint8_t*>( update_data + offset );
            //withdrawn_routes.emplace_back( update_data + offset + 1, nlri_len );
        }

        // parsing bgp path attributes
        std::vector<path_attr_t> paths;
        len = bswap16( *reinterpret_cast<uint16_t*>( update_data + offset ) );
        log( "Length of path attributes: "s + std::to_string( len ) );
        offset += sizeof( len );
        while( len > 0 ) {
            auto path = reinterpret_cast<path_attr_header*>( update_data + offset );
            paths.emplace_back( path );
            auto attr_len = 3 + ( path->extended_length == 1 ? ( bswap16( path->ext_len ) + 1 ) : path->len );
            len -= attr_len;
            offset += attr_len;
        };

        // parsing NLRI
        len = update_len - offset;
        log( "Length of NLRI: "s + std::to_string( len ) );
        std::vector<nlri> routes;
        while( len > 0 ) {
            if( offset >= update_len ) {
                log( "Error on parsing message" );
                return { {}, {}, {} };
            }
            uint8_t nlri_len = *reinterpret_cast<uint8_t*>( update_data + offset );
            uint32_t address = 0;
            auto bytes = nlri_len / 8;
            if( nlri_len % 8 != 0 ) {
                bytes++;
            }
            std::memcpy( &address, update_data + offset + 1, bytes );
            routes.emplace_back( address_v4 { bswap32( address ) }, nlri_len );
            len -= sizeof( nlri_len ) + bytes;
            offset += sizeof( nlri_len ) + bytes;
        }

        return { withdrawn_routes, paths, routes };
    }
};

#endif