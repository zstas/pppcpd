#include "main.hpp"

void vppcom_worker::callback( boost::system::error_code &ec ) {
    if( ec ) {
        log( "Error on async wait: "s + ec.message() );
    }

    struct epoll_event vcl_events[ 10 ];
    int num = vppcom_epoll_wait( fd, vcl_events, 10, 0 );
    if( num < 0 ) {
        log( "Error on vppcom_epoll_wait" );
        return;
    }
    for( int i = 0; i < num; i++ ) {
        auto &cur_event = vcl_events[ i ];
        auto event_fd = cur_event.data.u32;
        if( cur_event.events & EPOLLIN ) {
            auto accepted_sess = vppcom_session_accept( event_fd, nullptr, 0 );
        }
    }
}

vppcom_socket::vppcom_socket( uint16_t port ) {
    socket_handler = vppcom_session_create( 0, 1 );
    log( "session_create: "s + std::to_string( socket_handler ) );
    vppcom_endpt_t enp;
    uint32_t addr = 0;
    enp.parent_handle = 0;
    enp.ip = reinterpret_cast<uint8_t*>( &addr );
    enp.is_ip4 = 1;
    enp.port = bswap16( port );
    enp.is_cut_thru = 0;

    int ret = vppcom_session_bind( socket_handler, &enp );
    log( "session_bind: "s + std::to_string( ret ) );

    ret = vppcom_session_listen( socket_handler, 0 );
    log( "session_listen: "s + std::to_string( ret ) );
}