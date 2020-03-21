#include "utils.hpp"
#include "packet.hpp"
#include "config.hpp"
#include "fsm.hpp"

struct bgp_connection : public std::enable_shared_from_this<bgp_connection> {
    std::array<uint8_t,65535> buffer;
    socket_tcp sock;
    global_conf &gconf;
    bgp_neighbour_v4 &conf;
    bgp_fsm fsm;

    bgp_connection( socket_tcp s, global_conf &g, bgp_neighbour_v4 &c ):
        sock( std::move( s ) ),
        gconf( g ),
        conf( c ),
        fsm( sock.get_io_context(), false )
    {
        fsm.HoldTime = gconf.hold_time;
        if( conf.hold_time.has_value() ) {
            fsm.HoldTime = *conf.hold_time;
        }
    }

    ~bgp_connection() {
        log( "destructor bgp_connection" );
    }

    void start();
    void on_keepalive_timer( error_code ec );
    void start_keepalive_timer();

    void on_receive( error_code ec, std::size_t length );
    void on_send( std::shared_ptr<std::vector<uint8_t>> pkt, error_code ec, std::size_t length );
    void do_read();

    void rx_open( bgp_packet &pkt );
    void tx_open();

    void rx_keepalive( bgp_packet &pkt );
    void tx_keepalive();
};