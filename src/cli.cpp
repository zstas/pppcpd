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
    case CLI_CMD::GET_PPPOE_SESSIONS: {
        GET_PPPOE_SESSION_RESP val;
        for( auto const &[ k, v ]: runtime->activeSessions ) {
            PPPOE_SESSION_DUMP d;
            d.aaa_session_id = v.aaa_session_id;
            d.session_id = v.session_id;
            d.cookie = v.cookie;
            d.username = v.username;
            d.address = v.address;
            d.ifindex = v.ifindex;
            d.vrf = v.vrf;
            d.unnumbered = v.unnumbered;
            val.sessions.push_back( std::move( d ) );
        }
        out_msg.data = serialize( val );
        break;
    }
    default:
        out_msg.error = "Can't process this command";
        break;
    }

    auto out_string { serialize( out_msg ) };
    out_string += "\r\n\r\n";
    auto output = std::make_shared<std::string>( std::move( out_string ) );
    
    do_write( output );
}