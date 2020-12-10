#include <iostream>
#include <string>
#include <boost/asio.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/network_v4.hpp>

using address_v4_t = boost::asio::ip::address_v4;
using network_v4_t = boost::asio::ip::network_v4;

#include <boost/serialization/serialization.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/optional.hpp>
#include <boost/serialization/array.hpp>

#include "pppctl.hpp"
#include "cli.hpp"
#include "string_helpers.hpp"

inline constexpr char greeting[] { "pppctl# " };
inline constexpr char unix_socket_path[] { "/var/run/pppcpd.sock" };

CLIClient::CLIClient( boost::asio::io_context &i, const std::string &path ):
    io( i ),
    endpoint( path ),
    socket( i )
{
    socket.connect( endpoint );
    if( !socket.is_open() ) {
        throw std::runtime_error( "Can't connect to unix socket" );
    }
}

void CLIClient::process_input( const std::string &input ) {
    CLI_MSG out_msg;
    out_msg.type = CLI_CMD_TYPE::REQUEST;
    out_msg.cmd = CLI_CMD::GET_VPP_IFACES;
    auto out = serialize( out_msg ) + "\r\n\r\n";

    boost::asio::write( socket, boost::asio::buffer( out ) );
    std::string buf;
    auto n = boost::asio::read_until( socket, boost::asio::dynamic_buffer( buf ), "\r\n\r\n" );

    auto result = deserialize<CLI_MSG>( buf );
    if( !result.error.empty() ) {
        std::cout << "Error: " << result.error << std::endl;
    }
    switch( result.cmd ) {
    case CLI_CMD::GET_PPPOE_SESSIONS: {
        auto resp = deserialize<GET_PPPOE_SESSION_RESP>( result.data );
        std::cout << resp << std::endl;
        break;
    }
    case CLI_CMD::GET_AAA_SESSIONS:
    case CLI_CMD::GET_VERSION:
    break;
    case CLI_CMD::GET_VPP_IFACES: {
        auto resp = deserialize<GET_VPP_IFACES_RESP>( result.data );
        std::cout << resp << std::endl;
        break;
    }
    }
}

int main( int argc, char *argv[] ) {
    std::cout << "Control utility of ppp control daemon" << std::endl;
    std::string cmd;

    try {
        boost::asio::io_context io;

        CLIClient cli { io, unix_socket_path };

        while( cmd != "exit" ) {
            std::cout << greeting;
            std::getline( std::cin, cmd );
            cli.process_input( cmd );
        }

    } catch( std::exception &e ) {
        std::cerr << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}