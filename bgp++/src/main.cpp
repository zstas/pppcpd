#include "main.hpp"

main_loop::main_loop( int port ):
    accpt( io, endpoint( boost::asio::ip::tcp::v4(), port ) ),
    sock( io )
{}

void main_loop::run() {
    accpt.async_accept( sock, std::bind( &main_loop::on_accept, this, std::placeholders::_1 ) );
    io.run();
}

void main_loop::on_accept( error_code ec ) {
    if( ec ) {
        std::cerr << "Error on accepting new connection: "s + ec.message() << std::endl;
    }
    conns.emplace_back( std::move( sock ) );
}

int main( int argc, char *argv[] ) {
    try { 
        main_loop loop { 179 };
        loop.run();
    } catch( std::exception &e ) {
        std::cerr << "Error on run event loop: "s + e.what() << std::endl;
    }
    return 0;
}