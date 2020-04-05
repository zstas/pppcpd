#include "main.hpp"

vppcom_service::vppcom_service( io_context &ctx ):
    boost::asio::io_service::service( ctx ),
    work( new boost::asio::io_service::work( async_io_service ) ),
    thread( boost::bind( &boost::asio::io_service::run, &async_io_service) )
{
    auto ret = vppcom_app_create( "bgp++ vppcom" );
    log( "app_create: "s + std::to_string( ret ) );
    epoll_fd = vppcom_epoll_create();
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
    int num = vppcom_epoll_wait( epoll_fd, vcl_events, 10, 0 );
    if( num < 0 ) {
        log( "Error on vppcom_epoll_wait" );
        return;
    }

    for( auto const &ev: vcl_events ) {
        auto event_fd = ev.data.fd;
        if( ev.events & EPOLLIN ) {
            process_events( event_fd, op_type::READ );
        }
        if( ev.events & EPOLLOUT ) {
            process_events( event_fd, op_type::WRITE );
        }
        if( ev.events & EPOLLHUP ) {
            process_events( event_fd, op_type::ERROR );
        }
            if( auto const &listener = listeners.find( event_fd ); listener != listeners.end() ) {
                vppcom_endpt_t peer_endpt;
                auto new_session = vppcom_session_accept( event_fd, &peer_endpt, O_NONBLOCK );
                sessions.try_emplace( event_fd, event_fd, listener->second.local, peer_endpt );

                struct epoll_event event;
                memset( &event, 0, sizeof( event ) );
                event.events = EPOLLIN | EPOLLOUT;
                event.data.u32 = new_session;

                auto ret = vppcom_epoll_ctl( epoll_fd, EPOLL_CTL_ADD, new_session, &event );
                if( ret != VPPCOM_OK ) {
                    log( "Cannot add event to epoll" );
                }
                
            }
    }
}

void vppcom_service::process_events( uint32_t fd, op_type op ) {
    for( auto const &ev: scheduled_ops ) {
        if( ev.socket == fd && ev.type == op ) {
            ev.func(  );
            return;
        }
    }
    incoming_ops.emplace_back( fd, op );
}

void vppcom_listener::async_accept( accept_handler func ) {
    //io.post();
    
}

void vppcom_worker::callback( boost::system::error_code &ec ) {
    if( ec ) {
        log( "Error on async wait: "s + ec.message() );
    }
}   
