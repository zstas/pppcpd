#include <iostream>
#include <string>
#include <boost/asio.hpp>

#include "pppctl.hpp"
#include "cli.hpp"

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

std::string CLIClient::process_input( const std::string &input ) {
    CLI_MSG out_msg;
    out_msg.type = CLI_CMD_TYPE::REQUEST;
    out_msg.cmd = CLI_CMD::GET_PPPOE_SESSIONS;
    auto out = serialize( out_msg );

    boost::asio::write( socket, boost::asio::buffer( out ) );
    std::string buf;
    auto n = boost::asio::read_until( socket, boost::asio::dynamic_buffer( buf ), "\r\n\r\n" );

    return buf;
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
            std::cout << cli.process_input( cmd );
        }

    } catch( std::exception &e ) {
        std::cerr << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}