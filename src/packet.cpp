#include <vector>

#include "packet.hpp"
#include "net_integer.hpp"
#include "ethernet.hpp"

std::set<LCP_OPT_HDR*> PPP_LCP::parseLCPOptions() {
    std::set<LCP_OPT_HDR*> options;
    size_t offset = 0;
    do {
        auto opt = reinterpret_cast<LCP_OPT_HDR*>( data + offset );
        offset += opt->len;
    } while( offset + sizeof( *this ) < bswap( length ) );
    return options;
}

std::set<IPCP_OPT_HDR*> PPP_LCP::parseIPCPOptions() {
    std::set<IPCP_OPT_HDR*> options;
    size_t offset = 0;
    while( offset + sizeof( *this ) < bswap( length ) ) {
        auto opt = reinterpret_cast<IPCP_OPT_HDR*>( data + offset );
        offset += opt->len;
        options.emplace( opt );
    } 
    return options;
}

void LCP_OPT_1B::set( LCP_OPTIONS o, uint8_t v ) {
    opt = o;
    val = v;
    len = 3;
}

void LCP_OPT_2B::set( LCP_OPTIONS o, uint16_t v ) {
    opt = o;
    val = bswap( v );
    len = 4;
}

void LCP_OPT_3B::set( LCP_OPTIONS o, uint16_t v, uint8_t v2 ) {
    opt = o;
    val = bswap( v );
    val_additional = v2;
    len = 5;
}

void LCP_OPT_4B::set( LCP_OPTIONS o, uint32_t v ) {
    opt = o;
    val = bswap( v );
    len = 6;
}

void IPCP_OPT_4B::set( IPCP_OPTIONS o, uint32_t v ) {
    opt = o;
    val = bswap( v );
    len = 6;
}