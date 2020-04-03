#include "main.hpp"

vppcom_service::vppcom_service( io_context &ctx ):
    boost::asio::io_service::service( ctx ),
    work( new boost::asio::io_service::work( async_io_service ) ),
    thread( boost::bind( &boost::asio::io_service::run, &async_io_service) )
{
    auto ret = vppcom_app_create( "bgp++ vppcom" );
    log( "app_create: "s + std::to_string( ret ) );
    fd = vppcom_epoll_create();
}

vppcom_service::~vppcom_service() {
    work.reset();
    async_io_service.stop();
    thread.join();
}

void vppcom_service::start() {
    async_io_service.post( boost::bind( &vppcom_service::run_epoll, this ) );
}

void vppcom_service::run_epoll() {
    struct epoll_event vcl_events[ 10 ];
    int num = vppcom_epoll_wait( fd, vcl_events, 10, 0 );
    if( num < 0 ) {
        log( "Error on vppcom_epoll_wait" );
        return;
    }
    for( auto const &ev: vcl_events ) {
        auto event_fd = ev.data.u32;
        if( ev.events & EPOLLIN ) {
            async_io_service.post();
        }
    }
}

void vppcom_worker::callback( boost::system::error_code &ec ) {
    if( ec ) {
        log( "Error on async wait: "s + ec.message() );
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