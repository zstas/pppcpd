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
        log( "OPEN message" );
        rx_open( pkt );
        break;
    case bgp_type::KEEPALIVE:
        log( "KEEPALIVE message" );
        break;
    case bgp_type::UPDATE:
        log( "UPDATE message" );
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
    open->hold_time = 180;
    open->len = 0;

    // send this msg
    sock.async_send( boost::asio::buffer( *pkt_buf ), std::bind( &bgp_connection::on_send, shared_from_this(), pkt_buf, std::placeholders::_1, std::placeholders::_2 ) );
}

void bgp_connection::on_send( std::shared_ptr<std::vector<uint8_t>> pkt, error_code ec, std::size_t length ) {
    if( ec ) {
        log( "Error on sending packet: "s + ec.message() );
        return;
    }
    log( "Successfully sent a message with size: "s + std::to_string( length ) );
    fsm.state = FSM_STATE::OPENSENT;
}