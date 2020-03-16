#include "utils.hpp"

struct bgp_connection : public std::enable_shared_from_this<bgp_connection> {
    std::array<uint8_t,65535> buffer;
    socket_tcp sock;

    bgp_connection( socket_tcp s ):
        sock( std::move( s ) ) 
    {}

    void start();
    void on_receive( error_code ec, std::size_t length );
    void on_send();
    void do_read();
};