#include "cli.hpp"

CLIServer::CLIServer( boost::asio::io_context &io_context, const std::string &path ): 
    acceptor_( io_context, stream_protocol::endpoint( path ) )
{
    do_accept();
}

void CLIServer::do_accept() {
    acceptor_.async_accept(
        [this](boost::system::error_code ec, stream_protocol::socket socket) {
            if (!ec) {
                std::make_shared<CLISession>( std::move( socket ) )->start();
            }
        do_accept();
    });
}

void CLISession::start() {
    do_read();
}

void CLISession::do_read() {
    auto self( shared_from_this() );
    socket_.async_read_some(
        boost::asio::buffer(data_),
        [ this, self ]( boost::system::error_code ec, std::size_t length ) {
            if( !ec ) {
                do_write( length );
            }
        }
    );
}

void CLISession::do_write( std::size_t length ) {
    auto self( shared_from_this() );
    boost::asio::async_write(
        socket_,
        boost::asio::buffer(data_, length),
        [ this, self ]( boost::system::error_code ec, std::size_t ) {
            if( !ec ) {
                do_read();
            }
        }
    );
}