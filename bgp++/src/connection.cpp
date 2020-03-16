#include "main.hpp"

void bgp_connection::start() {
    auto const &endpoint = sock.remote_endpoint();
    log( "Incoming connection: "s + endpoint.address().to_string() + " "s + std::to_string( endpoint.port() ) );
    do_read();
}

void bgp_connection::on_receive( error_code ec, std::size_t length ) {
    if( ec ) {
        log( "Error on receiving data: "s + ec.message() );
    }
    log( "Received message of size: "s + std::to_string( length ) );
    do_read();
}

void bgp_connection::do_read() {
    sock.async_receive( boost::asio::buffer( buffer ), std::bind( &bgp_connection::on_receive, shared_from_this(), std::placeholders::_1, std::placeholders::_2 ) );
}