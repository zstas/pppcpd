#include "main.hpp"

bgp_fsm::bgp_fsm( io_context &io,  global_conf &g, bgp_neighbour_v4 &c ):
    state( FSM_STATE::IDLE ),
    gconf( g ),
    conf( c ),
    ConnectRetryTimer( io ),
    HoldTimer( io ),
    KeepaliveTimer( io )
{
    HoldTime = gconf.hold_time;
    if( conf.hold_time.has_value() ) {
        HoldTime = *conf.hold_time;
    }
}

void bgp_fsm::place_connection( socket_tcp s ) {
    sock.emplace( std::move( s ) );
    auto const &endpoint = sock->remote_endpoint();
    log( "Incoming connection: "s + endpoint.address().to_string() + " "s + std::to_string( endpoint.port() ) );
    do_read();
    tx_open();
}

void bgp_fsm::start_keepalive_timer() {
    KeepaliveTimer.expires_from_now( std::chrono::seconds( KeepaliveTime ) );
    KeepaliveTimer.async_wait( std::bind( &bgp_fsm::on_keepalive_timer, shared_from_this(), std::placeholders::_1 ) );
}

void bgp_fsm::on_keepalive_timer( error_code ec ) {
    log( "Periodic KEEPALIVE" );
    if( sock.has_value() ) {
        tx_keepalive();
        start_keepalive_timer();
    } else {
        log( "Lost connection" );
        // todo change state
    }
}

void bgp_fsm::rx_open( bgp_packet &pkt ) {
    auto open = pkt.get_open();
    if( !sock.has_value() ) {
        log( "Cannot acquire connection" );
        // todo: do something!
        return;
    }

    log( "Incoming OPEN packet from: "s + sock->remote_endpoint().address().to_string() );
    log( "BGP version: "s + std::to_string( open->version ) );
    log( "Router ID: "s + address_v4( bswap32( open->bgp_id ) ).to_string() );
    log( "Hold time: "s + std::to_string( bswap16( open->hold_time ) ) );

    if( bswap16( open->my_as ) != conf.remote_as ) {
        log( "Incorrect AS: "s + std::to_string( bswap16( open->my_as ) ) + ", we expected: "s + std::to_string( conf.remote_as ) );
        sock->close();
        return;
    }

    HoldTime = std::min( bswap16( open->hold_time ), HoldTime );
    KeepaliveTime = HoldTime / 3;
    log( "Negotiated timers - hold_time: "s + std::to_string( HoldTime ) + " keepalive_time: "s + std::to_string( KeepaliveTime ) );

    tx_keepalive();
    state = FSM_STATE::OPENCONFIRM;
}

void bgp_fsm::tx_open() {
    if( !sock.has_value() ) {
        log( "Cannot acquire connection" );
        // todo: do something!
        return;
    }

    auto len = sizeof( bgp_header ) + sizeof( bgp_open );
    auto pkt_buf = std::make_shared<std::vector<uint8_t>>();
    pkt_buf->resize( len );
    bgp_packet pkt { pkt_buf->data(), pkt_buf->size() };

    // header
    auto header = pkt.get_header();
    header->type = bgp_type::OPEN;
    header->length = bswap16( len );
    std::fill( header->marker.begin(), header->marker.end(), 0xFF );

    // open body
    auto open = pkt.get_open();
    open->version = 4;
    open->bgp_id = bswap32( gconf.bgp_router_id.to_uint() );
    open->my_as = bswap16( gconf.my_as );
    if( conf.hold_time.has_value() ) {
        open->hold_time = bswap16( *conf.hold_time );
    } else {
        open->hold_time = bswap16( gconf.hold_time );
    }
    open->len = 0;

    // send this msg
    sock->async_send( boost::asio::buffer( *pkt_buf ), std::bind( &bgp_fsm::on_send, shared_from_this(), pkt_buf, std::placeholders::_1, std::placeholders::_2 ) );
    state = FSM_STATE::OPENSENT;
}

void bgp_fsm::on_send( std::shared_ptr<std::vector<uint8_t>> pkt, error_code ec, std::size_t length ) {
    if( ec ) {
        log( "Error on sending packet: "s + ec.message() );
        return;
    }
    log( "Successfully sent a message with size: "s + std::to_string( length ) );
}

void bgp_fsm::tx_keepalive() {
    if( !sock.has_value() ) {
        log( "Cannot acquire connection" );
        // todo: do something!
        return;
    }

    log( "Sending KEEPALIVE to peer: "s + sock->remote_endpoint().address().to_string() );
    auto len = sizeof( bgp_header );
    auto pkt_buf = std::make_shared<std::vector<uint8_t>>();
    pkt_buf->resize( len );
    bgp_packet pkt { pkt_buf->data(), pkt_buf->size() };

    // header
    auto header = pkt.get_header();
    header->type = bgp_type::KEEPALIVE;
    header->length = bswap16( len );
    std::fill( header->marker.begin(), header->marker.end(), 0xFF );

    // send this msg
    sock->async_send( boost::asio::buffer( *pkt_buf ), std::bind( &bgp_fsm::on_send, shared_from_this(), pkt_buf, std::placeholders::_1, std::placeholders::_2 ) );
}

void bgp_fsm::rx_keepalive( bgp_packet &pkt ) {
    if( !sock.has_value() ) {
        log( "Cannot acquire connection" );
        // todo: do something!
        return;
    }

    if( state == FSM_STATE::OPENCONFIRM || state == FSM_STATE::OPENSENT ) {
        log( "BGP goes to ESTABLISHED state with peer: "s + sock->remote_endpoint().address().to_string() );
        state = FSM_STATE::ESTABLISHED;
        start_keepalive_timer();
    } else if( state != FSM_STATE::ESTABLISHED ) {
        log( "Received a KEEPALIVE in incorrect state, closing connection" );
        sock->close();
    }
    log( "Received a KEEPALIVE message" );
}

void bgp_fsm::rx_update( bgp_packet &pkt ) {
    auto [ withdrawn_routes, path_attrs, routes ] = pkt.process_update();
    log(    "Received UPDATE message with withdrawn routes, paths and routes: "s + 
            std::to_string( withdrawn_routes.size() ) + " "s + 
            std::to_string( path_attrs.size() ) + " "s + 
            std::to_string( routes.size() ) );

    for( auto &attr: path_attrs ) {
        log( "Received path attribute: "s + attr.to_string() );
    }
    for( auto &route: routes ) {
        log( "Received route: "s + route.to_string() );
    }
}

void bgp_fsm::on_receive( error_code ec, std::size_t length ) {
    if( ec ) {
        log( "Error on receiving data: "s + ec.message() );
        return;
    }

    if( !sock.has_value() ) {
        log( "Cannot acquire connection" );
        // todo: do something!
        return;
    }

    log( "Received message of size: "s + std::to_string( length ) );
    bgp_packet pkt { buffer.begin(), length };
    auto bgp_header = pkt.get_header();
    if( std::any_of( bgp_header->marker.begin(), bgp_header->marker.end(), []( uint8_t el ) { return el != 0xFF; } ) ) {
        log( "Wrong BGP marker in header!" );
        return;
    }
    switch( bgp_header->type ) {
    case bgp_type::OPEN:
        rx_open( pkt );
        break;
    case bgp_type::KEEPALIVE:
        rx_keepalive( pkt );
        break;
    case bgp_type::UPDATE:
        rx_update( pkt );
        break;
    case bgp_type::NOTIFICATION:
        log( "NOTIFICATION message" );
        break;
    case bgp_type::ROUTE_REFRESH:
        log( "ROUTE_REFRESH message" );
        break;
    }
    do_read();
}

void bgp_fsm::do_read() {
    if( !sock.has_value() ) {
        log( "Cannot acquire connection" );
        // todo: do something!
        return;
    }

    sock->async_receive( boost::asio::buffer( buffer ), std::bind( &bgp_fsm::on_receive, shared_from_this(), std::placeholders::_1, std::placeholders::_2 ) );
}
