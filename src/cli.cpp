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

void CLISession::do_write( std::string &out ) {
    auto self( shared_from_this() );
    out.append( "\r\n\r\n" );
    socket_.async_write_some(
        boost::asio::buffer( out.data(), out.size() ),
        [ this, self ]( boost::system::error_code ec, std::size_t ) {
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
    std::string output;
    std::ostringstream stream;
    if( startWith( cmd, "show subscribers" ) ) {
        stream.width( 20 );
        stream << std::setw( 6 ) << std::setfill( ' ' ) << std::left << "ID";
        stream << std::setw( 20 ) << std::setfill( ' ' ) << std::left << "MAC";
        stream << std::setw( 20 ) << std::setfill( ' ' ) << std::left << "Username"; 
        stream << std::setw( 20 ) << std::setfill( ' ' ) << std::left << "IP-Address"; 
        stream << std::endl;
        for( auto const &[ key, session ]: runtime->activeSessions ) {
            stream << std::setw( 6 ) << std::setfill( ' ' ) << std::left << session.session_id;
            stream << std::setw( 20 ) << std::setfill( ' ' ) << std::left << session.encap.destination_mac;
            stream << std::setw( 20 ) << std::setfill( ' ' ) << std::left << session.username;
            stream << std::setw( 20 ) << std::setfill( ' ' ) << std::left << address_v4_t( session.address );
            stream << std::endl;
        }
        output = stream.str();
    } else {
        output = "unknown command";
    }
    do_write( output );
}