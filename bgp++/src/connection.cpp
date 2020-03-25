#include "main.hpp"

void bgp_connection::start() {
    auto const &endpoint = sock.remote_endpoint();
    log( "Incoming connection: "s + endpoint.address().to_string() + " "s + std::to_string( endpoint.port() ) );
    do_read();
    tx_open();
}

void bgp_connection::on_receive( error_code ec, std::size_t length ) {
    if( ec ) {
        log( "Error on receiving data: "s + ec.message() );
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

void bgp_connection::do_read() {
    sock.async_receive( boost::asio::buffer( buffer ), std::bind( &bgp_connection::on_receive, shared_from_this(), std::placeholders::_1, std::placeholders::_2 ) );
}

void bgp_connection::rx_open( bgp_packet &pkt ) {
    auto open = pkt.get_open();

    log( "Incoming OPEN packet from: "s + sock.remote_endpoint().address().to_string() );
    log( "BGP version: "s + std::to_string( open->version ) );
    log( "Router ID: "s + address_v4( bswap32( open->bgp_id ) ).to_string() );
    log( "Hold time: "s + std::to_string( bswap16( open->hold_time ) ) );

    if( bswap16( open->my_as ) != conf.remote_as ) {
        log( "Incorrect AS: "s + std::to_string( bswap16( open->my_as ) ) + ", we expected: "s + std::to_string( conf.remote_as ) );
        sock.close();
        return;
    }

    fsm.HoldTime = std::min( bswap16( open->hold_time ), fsm.HoldTime );
    fsm.KeepaliveTime = fsm.HoldTime / 3;
    log( "Negotiated timers - hold_time: "s + std::to_string( fsm.HoldTime ) + " keepalive_time: "s + std::to_string( fsm.KeepaliveTime ) );

    tx_keepalive();
    fsm.state = FSM_STATE::OPENCONFIRM;
}

void bgp_connection::tx_open() {
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
    sock.async_send( boost::asio::buffer( *pkt_buf ), std::bind( &bgp_connection::on_send, shared_from_this(), pkt_buf, std::placeholders::_1, std::placeholders::_2 ) );
    fsm.state = FSM_STATE::OPENSENT;
}

void bgp_connection::on_send( std::shared_ptr<std::vector<uint8_t>> pkt, error_code ec, std::size_t length ) {
    if( ec ) {
        log( "Error on sending packet: "s + ec.message() );
        return;
    }
    log( "Successfully sent a message with size: "s + std::to_string( length ) );
}

void bgp_connection::tx_keepalive() {
    log( "Sending KEEPALIVE to peer: "s + sock.remote_endpoint().address().to_string() );
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
    sock.async_send( boost::asio::buffer( *pkt_buf ), std::bind( &bgp_connection::on_send, shared_from_this(), pkt_buf, std::placeholders::_1, std::placeholders::_2 ) );
}

void bgp_connection::rx_keepalive( bgp_packet &pkt ) {
    if( fsm.state == FSM_STATE::OPENCONFIRM || fsm.state == FSM_STATE::OPENSENT ) {
        log( "BGP goes to ESTABLISHED state with peer: "s + sock.remote_endpoint().address().to_string() );
        fsm.state = FSM_STATE::ESTABLISHED;
        start_keepalive_timer();
    } else if( fsm.state != FSM_STATE::ESTABLISHED ) {
        log( "Received a KEEPALIVE in incorrect state, closing connection" );
        sock.close();
    }
    log( "Received a KEEPALIVE message" );
}

void bgp_connection::on_keepalive_timer( error_code ec ) {
    log( "Periodic KEEPALIVE" );
    tx_keepalive();
    start_keepalive_timer();
}

void bgp_connection::start_keepalive_timer() {
    fsm.KeepaliveTimer.expires_from_now( std::chrono::seconds( fsm.KeepaliveTime ) );
    fsm.KeepaliveTimer.async_wait( std::bind( &bgp_connection::on_keepalive_timer, shared_from_this(), std::placeholders::_1 ) );
}

void bgp_connection::rx_update( bgp_packet &pkt ) {
    auto const &[ withdrawn_routes, path_attrs, routes ] = pkt.process_update();
    log(    "Received UPDATE message with withdrawn routes, paths and routes: "s + 
            std::to_string( withdrawn_routes.size() ) + " "s + 
            std::to_string( path_attrs.size() ) + " "s + 
            std::to_string( routes.size() ) );

    for( auto const &attr: path_attrs ) {
        log( "Received path attribute: "s + attr.to_string() );
    }
    for( auto const &route: routes ) {
        log( "Received route: "s + route.to_string() );
    }
}