#include <memory>
#include <boost/serialization/serialization.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/optional.hpp>

#include "cli.hpp"
#include "runtime.hpp"
#include "string_helpers.hpp"

extern std::shared_ptr<PPPOERuntime> runtime;

CLIServer::CLIServer( boost::asio::io_context &io_context, const std::string &path ): 
    acceptor_( io_context, stream_protocol::endpoint( path ) )
{
    do_accept();
}

void CLIServer::do_accept() {
    acceptor_.async_accept(
        [ this ]( boost::system::error_code ec, stream_protocol::socket socket ) {
            if( !ec ) {
                runtime->logger->logInfo() << LOGS::MAIN << "CLI new connection" << std::endl;
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
        boost::asio::buffer( data_ ),
        [ this, self ]( boost::system::error_code ec, std::size_t length ) {
            if( !ec ) {
                run_cmd( { data_.begin(), data_.begin() + length } );
            }
        }
    );
}

void CLISession::do_write( std::shared_ptr<std::string> &out ) {
    auto self( shared_from_this() );
    socket_.async_write_some(
        boost::asio::buffer( out->data(), out->size() ),
        [ this, self, out ]( boost::system::error_code ec, std::size_t ) {
            if( !ec ) {
                do_read();
            }
        }
    );
}

inline bool startWith( const std::string &s1, const std::string &s2 ) {
    return s1.find( s2 ) == 0;
}

void CLISession::run_cmd( const std::string &cmd ) {
    CLI_MSG out_msg;

    auto in_msg = deserialize<CLI_MSG>( cmd );
    switch( in_msg.cmd ) {
    case CLI_CMD::GET_VERSION:
        break;
    default:
        out_msg.error = "Can't process this command";
        break;
    }

    auto output = std::make_shared<std::string>( serialize( out_msg ) );
    
    do_write( output );
}