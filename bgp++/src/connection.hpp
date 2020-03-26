#include "utils.hpp"
#include "packet.hpp"
#ifndef CONNECTION_HPP_
#define CONNECTION_HPP_

struct bgp_connection : public std::enable_shared_from_this<bgp_connection> {
    std::array<uint8_t,65535> buffer;
    socket_tcp sock;

    bgp_connection( socket_tcp s ):
        sock( std::move( s ) )
    {}

    ~bgp_connection() {
        log( "destructor bgp_connection" );
    }
};

#endif